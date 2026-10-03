using SentryNet.Core;

namespace SentryNet.Tests;

public sealed class EngineTests
{
    private sealed class FakeScanner(string name, bool fail = false) : IScanner
    {
        public string Name => name;
        public int Calls;
        public Task<ProbeResult> ScanAsync(ResolvedTarget target, ScanOptions options, CancellationToken ct)
        {
            Interlocked.Increment(ref Calls);
            ct.ThrowIfCancellationRequested();
            if (fail) throw new IOException("fixture failure");
            return Task.FromResult(new ProbeResult(Name, target.Address, ProbeStatus.Complete, [], [new(23, "tcp", "telnet")]));
        }
    }
    [Fact]
    public async Task UnauthorizedScanNeverInvokesScanner()
    {
        var scanner = new FakeScanner("tcp"); var engine = new ScanEngine([scanner], []);
        await Assert.ThrowsAsync<ArgumentException>(() => engine.ScanAsync(TestData.Options() with { Authorized = false }));
        Assert.Equal(0, scanner.Calls);
    }
    [Fact]
    public async Task UnknownScannerFailsBeforeExecution()
    {
        var scanner = new FakeScanner("tcp");
        await Assert.ThrowsAsync<ArgumentException>(() => new ScanEngine([scanner], []).ScanAsync(TestData.Options() with { Scanners = ["unknown"] }));
        Assert.Equal(0, scanner.Calls);
    }
    [Fact]
    public async Task ScannerFailurePreservesOtherResults()
    {
        var engine = new ScanEngine([new FakeScanner("tcp"), new FakeScanner("broken", true)], [new BuiltinRules()]);
        var report = await engine.ScanAsync(TestData.Options() with { Scanners = ["tcp", "broken"] });
        Assert.Equal(2, report.Probes.Count); Assert.False(report.Complete);
        Assert.Single(report.Findings); Assert.NotEmpty(report.PolicyFingerprint);
    }
    [Fact]
    public async Task DisablesIndividualBuiltinRulesAndOverridesSeverity()
    {
        var engine = new ScanEngine([new FakeScanner("tcp")], [new BuiltinRules()]);
        Assert.Empty((await engine.ScanAsync(TestData.Options() with { DisabledRules = ["NET001"] })).Findings);
        var report = await engine.ScanAsync(TestData.Options() with { SeverityOverrides = new() { ["NET001"] = Severity.Low } });
        Assert.Equal(Severity.Low, Assert.Single(report.Findings).Severity);
    }
    [Fact]
    public async Task CancellationIsNotConvertedIntoScannerError()
    {
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new ScanEngine([new FakeScanner("tcp")], []).ScanAsync(TestData.Options(), ct: cancellation.Token));
    }
    [Fact]
    public async Task DeduplicatesServiceFindingsAcrossScanners()
    {
        var report = await new ScanEngine([new FakeScanner("tcp"), new FakeScanner("nmap")], [new BuiltinRules()])
            .ScanAsync(TestData.Options() with { Scanners = ["tcp", "nmap"] });
        Assert.Single(report.Findings);
    }
}
