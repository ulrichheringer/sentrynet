using System.Collections.Concurrent;

namespace SentryNet.Core;

public sealed class ScanEngine
{
    private readonly IScanner[] scanners;
    private readonly IRule[] rules;
    public ScanEngine(IEnumerable<IScanner> scanners, IEnumerable<IRule> rules)
    {
        this.scanners = scanners.ToArray(); this.rules = rules.ToArray();
        if (this.scanners.Any(s => string.IsNullOrWhiteSpace(s.Name)) || this.scanners.Select(s => s.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != this.scanners.Length)
            throw new ArgumentException("Scanner names must be nonempty and unique; plugins cannot shadow built-in scanners.");
        if (this.rules.Any(r => string.IsNullOrWhiteSpace(r.Id)) || this.rules.Select(r => r.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count() != this.rules.Length)
            throw new ArgumentException("Rule provider IDs must be nonempty and unique.");
    }
    public IReadOnlyList<string> ScannerNames => scanners.Select(s => s.Name).ToArray();
    public async Task<ScanReport> ScanAsync(ScanOptions options, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        options.Validate();
        var selected = scanners.Where(s => options.Scanners.Contains(s.Name, StringComparer.OrdinalIgnoreCase)).ToArray();
        var unknown = options.Scanners.Where(n => !selected.Any(s => s.Name.Equals(n, StringComparison.OrdinalIgnoreCase))).ToArray();
        if (unknown.Length > 0) throw new ArgumentException($"Unknown scanners: {string.Join(", ", unknown)}");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(options.MaxDurationSeconds));
        var started = DateTimeOffset.UtcNow;
        var targets = await new ScopePolicy(options.Scope).ResolveAsync(options, deadline.Token);
        var results = new ConcurrentBag<ProbeResult>();
        await Parallel.ForEachAsync(targets, new ParallelOptions { MaxDegreeOfParallelism = options.Parallelism, CancellationToken = deadline.Token },
            async (target, token) =>
            {
                foreach (var scanner in selected)
                {
                    token.ThrowIfCancellationRequested();
                    progress?.Report($"{scanner.Name}: {target.Name} ({target.Address})");
                    try { results.Add((await scanner.ScanAsync(target, options, token)) with { TargetName = target.Name }); }
                    catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
                    catch (Exception ex) when (ex is not OutOfMemoryException)
                    { results.Add(new(scanner.Name, target.Address, ProbeStatus.Failed, [], [], ex.Message, target.Name)); }
                    await Task.Delay(options.DelayMs, token);
                }
            });
        var ordered = results.OrderBy(r => r.Asset, StringComparer.Ordinal).ThenBy(r => r.TargetName, StringComparer.Ordinal).ThenBy(r => r.Scanner, StringComparer.Ordinal).ToArray();
        var findings = rules.Where(r => !options.DisabledRules.Contains(r.Id, StringComparer.OrdinalIgnoreCase))
            .SelectMany(r => r.Evaluate(ordered)).Where(f => !options.DisabledRules.Contains(f.RuleId, StringComparer.OrdinalIgnoreCase))
            .Select(f => options.SeverityOverrides.TryGetValue(f.RuleId, out var severity) ? f with { Severity = severity } : f)
            .DistinctBy(f => f.Fingerprint).OrderByDescending(f => f.Severity).ThenBy(f => f.Fingerprint, StringComparer.Ordinal).ToArray();
        var signature = string.Join("\n", rules.OrderBy(r => r.Id, StringComparer.Ordinal).Select(r => r.PolicySignature));
        var fingerprint = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(signature)));
        return new("1.0", Guid.NewGuid(), started, DateTimeOffset.UtcNow, options, targets, ordered, findings, fingerprint);
    }
}
