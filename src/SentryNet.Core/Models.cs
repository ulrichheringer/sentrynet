using System.Text.Json;
using System.Text.Json.Serialization;

namespace SentryNet.Core;

public enum Severity { Info, Low, Medium, High, Critical }
public enum ProbeStatus { Complete, Failed, Skipped }
public sealed record Evidence(string Key, string Value, string Source, DateTimeOffset ObservedAt);
public sealed record Service(int Port, string Protocol, string Name, string? Product = null, string? Version = null);
public sealed record Finding(string RuleId, Severity Severity, string Title, string Asset, string Recommendation,
    IReadOnlyList<Evidence> Evidence, string? Reference = null)
{
    public string Fingerprint => $"{RuleId}|{Asset}";
}
public sealed record ProbeResult(string Scanner, string Asset, ProbeStatus Status,
    IReadOnlyList<Evidence> Evidence, IReadOnlyList<Service> Services, string? Error = null);
public sealed record ResolvedTarget(string Name, string Address);
public sealed record ScanOptions
{
    public string[] Targets { get; init; } = [];
    public string[] Scope { get; init; } = [];
    public bool Authorized { get; init; }
    public string AuthorizationReference { get; init; } = "";
    public string Client { get; init; } = "default";
    public string Engagement { get; init; } = "";
    public int[] Ports { get; init; } = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 5432, 6379, 8080, 8443];
    public string[] Scanners { get; init; } = ["dns", "tcp", "http", "tls"];
    public int Parallelism { get; init; } = 8;
    public int TimeoutMs { get; init; } = 3000;
    public int MaxHosts { get; init; } = 256;
    public int DelayMs { get; init; } = 50;
    public int MaxDurationSeconds { get; init; } = 600;
    public string? RulesFile { get; init; }
    public string[] DisabledRules { get; init; } = [];
    public Dictionary<string, Severity> SeverityOverrides { get; init; } = [];

    public void Validate(bool requireAuthorization = true)
    {
        if (requireAuthorization && (!Authorized || string.IsNullOrWhiteSpace(AuthorizationReference)))
            throw new ArgumentException("Active scans require --authorized and an authorization reference.");
        if (Targets.Length == 0 || Scope.Length == 0) throw new ArgumentException("Targets and explicit scope are required.");
        if (Parallelism is < 1 or > 64 || TimeoutMs is < 100 or > 60000 || MaxHosts is < 1 or > 4096 ||
            DelayMs is < 0 or > 60000 || MaxDurationSeconds is < 1 or > 86400)
            throw new ArgumentException("Invalid limits: parallelism 1..64, timeout 100..60000ms, hosts 1..4096, delay 0..60000ms, duration 1..86400s.");
        if (Ports.Length == 0 || Ports.Length > 4096 || Ports.Any(p => p is < 1 or > 65535))
            throw new ArgumentException("Specify 1..4096 ports in the range 1..65535.");
        if (Scanners.Length == 0) throw new ArgumentException("At least one scanner is required.");
        if (string.IsNullOrWhiteSpace(Client)) throw new ArgumentException("Client is required.");
    }
}
public sealed record ScanReport(string SchemaVersion, Guid Id, DateTimeOffset StartedAt, DateTimeOffset FinishedAt,
    ScanOptions Options, IReadOnlyList<ResolvedTarget> Targets, IReadOnlyList<ProbeResult> Probes,
    IReadOnlyList<Finding> Findings, string PolicyFingerprint = "")
{
    public bool Complete => Probes.All(p => p.Status == ProbeStatus.Complete);
}
public sealed record Change(string Kind, string Asset, string Description);
public sealed record ScanDiff(Guid BaselineId, Guid CurrentId, bool Comparable, string? Warning, IReadOnlyList<Change> Changes);
public interface IScanner
{
    string Name { get; }
    Task<ProbeResult> ScanAsync(ResolvedTarget target, ScanOptions options, CancellationToken cancellationToken);
}
public interface IRule
{
    string Id { get; }
    string PolicySignature => GetType().AssemblyQualifiedName ?? Id;
    IEnumerable<Finding> Evaluate(IReadOnlyList<ProbeResult> probes);
}
public interface IReportStore
{
    Task SaveAsync(ScanReport report, CancellationToken cancellationToken = default);
    Task<ScanReport> LoadAsync(string path, CancellationToken cancellationToken = default);
}
public static class JsonDefaults
{
    public static JsonSerializerOptions Options { get; } = new()
    {
        WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true, Converters = { new JsonStringEnumConverter() }
    };
}
