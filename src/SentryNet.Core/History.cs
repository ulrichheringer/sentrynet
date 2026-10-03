using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SentryNet.Core;

public sealed class FileReportStore(string root) : IReportStore
{
    public string Root { get; } = Path.GetFullPath(root);
    public string ClientDirectory(string client) => Path.Combine(Root, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(client)))[..16].ToLowerInvariant());
    public string ReportPath(ScanReport report) => Path.Combine(ClientDirectory(report.Options.Client), $"{report.StartedAt:yyyyMMddTHHmmssfffZ}-{report.Id}.json");
    public Task SaveAsync(ScanReport report, CancellationToken ct = default) => AtomicFile.WriteAsync(ReportPath(report), JsonSerializer.Serialize(report, JsonDefaults.Options), ct);
    public async Task<ScanReport> LoadAsync(string path, CancellationToken ct = default)
    {
        if (new FileInfo(path).Length > 100 * 1024 * 1024) throw new InvalidDataException("Report exceeds 100 MiB.");
        using var stream = File.OpenRead(path);
        var report = await JsonSerializer.DeserializeAsync<ScanReport>(stream, JsonDefaults.Options, ct) ?? throw new InvalidDataException("Empty report.");
        if (report.SchemaVersion != "1.0") throw new InvalidDataException($"Unsupported schema: {report.SchemaVersion}");
        if (report.Options is null || report.Targets is null || report.Probes is null || report.Findings is null)
            throw new InvalidDataException("Missing required report fields.");
        return report;
    }
    public async Task<IReadOnlyList<ScanReport>> ListAsync(string client, CancellationToken ct = default)
    {
        var path = ClientDirectory(client); if (!Directory.Exists(path)) return [];
        var result = new List<ScanReport>();
        foreach (var file in Directory.EnumerateFiles(path, "*.json")) result.Add(await LoadAsync(file, ct));
        return result.OrderByDescending(r => r.StartedAt).ToArray();
    }
}
public static class AtomicFile
{
    public static async Task WriteAsync(string path, string content, CancellationToken ct = default)
    {
        var full = Path.GetFullPath(path); Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        var temporary = full + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await File.WriteAllTextAsync(temporary, content, new UTF8Encoding(false), ct);
            ct.ThrowIfCancellationRequested();
            File.Move(temporary, full, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
public static class BaselineComparer
{
    public static ScanDiff Compare(ScanReport baseline, ScanReport current)
    {
        static string Set<T>(IEnumerable<T> items) => string.Join("|", items.Select(i => i?.ToString()).Order(StringComparer.Ordinal));
        var comparable = baseline.Options.Client == current.Options.Client && baseline.Options.Engagement == current.Options.Engagement &&
            Set(baseline.Targets) == Set(current.Targets) && Set(baseline.Options.Ports.Distinct()) == Set(current.Options.Ports.Distinct()) &&
            Set(baseline.Options.Scanners.Select(s => s.ToLowerInvariant())) == Set(current.Options.Scanners.Select(s => s.ToLowerInvariant())) &&
            Set(baseline.Options.DisabledRules) == Set(current.Options.DisabledRules) &&
            Set(baseline.Options.SeverityOverrides) == Set(current.Options.SeverityOverrides) && baseline.PolicyFingerprint == current.PolicyFingerprint &&
            !string.IsNullOrEmpty(current.PolicyFingerprint) && baseline.Complete && current.Complete;
        var changes = new List<Change>();
        var oldFindings = baseline.Findings.ToDictionary(f => f.Fingerprint);
        var newFindings = current.Findings.ToDictionary(f => f.Fingerprint);
        foreach (var f in newFindings.Values)
        {
            if (!oldFindings.TryGetValue(f.Fingerprint, out var old)) changes.Add(new("finding-added", f.Asset, $"{f.RuleId}: {f.Title}"));
            else if (old.Severity != f.Severity) changes.Add(new("severity-changed", f.Asset, $"{f.RuleId}: {old.Severity} -> {f.Severity}"));
            else if (Set(old.Evidence.Select(e => e.Key + "=" + e.Value)) != Set(f.Evidence.Select(e => e.Key + "=" + e.Value)))
                changes.Add(new("finding-evidence-changed", f.Asset, f.RuleId));
        }
        foreach (var f in oldFindings.Values.Where(f => !newFindings.ContainsKey(f.Fingerprint)))
            changes.Add(new(comparable ? "finding-resolved" : "finding-unconfirmed", f.Asset, $"{f.RuleId}: {f.Title}"));
        var oldServices = Inventory(baseline); var newServices = Inventory(current);
        foreach (var item in newServices)
        {
            if (!oldServices.TryGetValue(item.Key, out var old)) changes.Add(new("service-added", item.Key, item.Value));
            else if (old != item.Value) changes.Add(new("service-changed", item.Key, $"{old} -> {item.Value}"));
        }
        foreach (var item in oldServices.Where(s => !newServices.ContainsKey(s.Key)))
            changes.Add(new(comparable ? "service-removed" : "service-unconfirmed", item.Key, item.Value));
        var oldHosts = baseline.Targets.Select(t => t.Address).ToHashSet(); var newHosts = current.Targets.Select(t => t.Address).ToHashSet();
        foreach (var host in newHosts.Except(oldHosts)) changes.Add(new("target-added", host, "New resolved target."));
        foreach (var host in oldHosts.Except(newHosts)) changes.Add(new("target-removed", host, "Target absent from current resolution; this is not proof of an offline host."));
        var oldCertificates = Certificates(baseline); var newCertificates = Certificates(current);
        foreach (var cert in newCertificates)
            if (oldCertificates.TryGetValue(cert.Key, out var old) && old != cert.Value) changes.Add(new("certificate-changed", cert.Key, $"{old} -> {cert.Value}"));
        var oldDns = Dns(baseline); var newDns = Dns(current);
        foreach (var record in newDns)
            if (oldDns.TryGetValue(record.Key, out var old) && old != record.Value) changes.Add(new("dns-changed", record.Key, $"{old} -> {record.Value}"));
        return new(baseline.Id, current.Id, comparable, comparable ? null : "Coverage, client, engagement, rule policy or collection completeness differs. Missing findings/services are unconfirmed, not resolved.",
            changes.OrderBy(c => c.Kind, StringComparer.Ordinal).ThenBy(c => c.Asset, StringComparer.Ordinal).ToArray());
    }
    private static Dictionary<string, string> Inventory(ScanReport r) => r.Probes.SelectMany(p => p.Services.Select(s => new
        { Key = $"{p.Asset}/{s.Protocol}/{s.Port}", Value = $"{s.Name} {s.Product} {s.Version}".Trim(), Source = p.Scanner }))
        .GroupBy(s => s.Key).ToDictionary(g => g.Key, g => g.OrderBy(s => s.Source == "nmap" ? 0 : 1).First().Value);
    private static Dictionary<string, string> Certificates(ScanReport r) => r.Probes.SelectMany(p => p.Evidence.Where(e => e.Key.EndsWith(".sha256", StringComparison.Ordinal))
        .Select(e => (Key: p.Asset + "/" + e.Key, e.Value))).GroupBy(x => x.Key).ToDictionary(g => g.Key, g => g.First().Value);
    private static Dictionary<string, string> Dns(ScanReport r) => r.Probes.Where(p => p.Scanner == "dig").SelectMany(p => p.Evidence.Where(e => e.Key.StartsWith("dns.record.", StringComparison.Ordinal))
        .Select(e => (Key: p.Asset + "/" + e.Key, Value: NormalizeDns(e.Value)))).GroupBy(x => x.Key).ToDictionary(g => g.Key, g => g.First().Value);
    private static string NormalizeDns(string value) => string.Join("\n", value.Split('\n', StringSplitOptions.RemoveEmptyEntries)
        .Select(line => string.Join(" ", line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Where((_, index) => index != 1))).Order(StringComparer.Ordinal));
}
