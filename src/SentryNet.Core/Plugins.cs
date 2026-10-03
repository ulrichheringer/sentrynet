namespace SentryNet.Core;

/// <summary>Explicitly loaded, trusted in-process extensions. Implementations must honor scope and cancellation.</summary>
public interface ISentryNetPlugin
{
    string Name { get; }
    string Version { get; }
    IEnumerable<IScanner> CreateScanners();
    IEnumerable<IRule> CreateRules();
}

// Transport-neutral contracts for a future authenticated agent/API layer. No remote execution is enabled.
public sealed record ScanJob(Guid Id, string ClientId, string EngagementId, ScanOptions Options, DateTimeOffset ExpiresAt);
public sealed record AgentIdentity(string Id, string Version, string[] Capabilities);
public interface IScanDispatcher
{
    Task<ScanReport> DispatchAsync(ScanJob job, CancellationToken cancellationToken);
}
