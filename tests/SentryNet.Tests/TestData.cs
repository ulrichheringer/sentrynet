using SentryNet.Core;

namespace SentryNet.Tests;

internal static class TestData
{
    public static ScanOptions Options() => new() { Targets = ["127.0.0.1"], Scope = ["127.0.0.1"], Authorized = true, AuthorizationReference = "Owned loopback test fixture", Ports = [80], Scanners = ["tcp"], DelayMs = 0 };
    public static Evidence E(string key, string value, string scanner = "http") => new(key, value, scanner, new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
    public static ScanReport Report(params ProbeResult[] probes) => new("1.0", Guid.NewGuid(), DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, Options(), [new("127.0.0.1", "127.0.0.1")], probes, new BuiltinRules().Evaluate(probes).ToArray(), "test-policy-v1");
}
