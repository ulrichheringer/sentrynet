using System.Text.Json;
using SentryNet.Core;

namespace SentryNet.Tests;

public sealed class HistoryAndReportTests
{
    private static ProbeResult Open => new("tcp", "127.0.0.1", ProbeStatus.Complete, [TestData.E("tcp.23", "open", "tcp")], [new(23, "tcp", "telnet")]);
    [Fact]
    public void OnlyCompleteEquivalentCoverageResolvesFindings()
    {
        var baseline = TestData.Report(Open);
        var current = TestData.Report(new ProbeResult("tcp", "127.0.0.1", ProbeStatus.Complete, [], []));
        var diff = BaselineComparer.Compare(baseline, current);
        Assert.True(diff.Comparable);
        Assert.Contains(diff.Changes, c => c.Kind == "finding-resolved");
        Assert.Contains(diff.Changes, c => c.Kind == "service-removed");
    }
    [Fact]
    public void IncompleteScanDoesNotResolveFindings()
    {
        var baseline = TestData.Report(Open);
        var current = TestData.Report(new ProbeResult("tcp", "127.0.0.1", ProbeStatus.Failed, [], [], "timeout"));
        var diff = BaselineComparer.Compare(baseline, current);
        Assert.False(diff.Comparable);
        Assert.Contains(diff.Changes, c => c.Kind == "finding-unconfirmed");
        Assert.DoesNotContain(diff.Changes, c => c.Kind.EndsWith("resolved", StringComparison.Ordinal));
    }
    [Fact]
    public void DifferentClientOrRulePolicyIsNotComparable()
    {
        var baseline = TestData.Report(Open);
        Assert.False(BaselineComparer.Compare(baseline, baseline with { Options = baseline.Options with { Client = "other" } }).Comparable);
        Assert.False(BaselineComparer.Compare(baseline, baseline with { PolicyFingerprint = "different" }).Comparable);
    }
    [Fact]
    public void EvidenceTimestampsDoNotCreateChanges()
    {
        var baseline = TestData.Report(Open);
        var findings = baseline.Findings.Select(f => f with { Evidence = f.Evidence.Select(e => e with { ObservedAt = e.ObservedAt.AddHours(3) }).ToArray() }).ToArray();
        Assert.Empty(BaselineComparer.Compare(baseline, baseline with { Id = Guid.NewGuid(), Findings = findings }).Changes);
    }
    [Fact]
    public void DnsTtlChangeIsIgnoredButRecordChangesAreDetected()
    {
        ProbeResult Dns(string value) => new("dig", "127.0.0.1", ProbeStatus.Complete, [TestData.E("dns.record.a", value, "dig")], []);
        var baseline = TestData.Report(Dns("example.test. 300 IN A 192.0.2.1"));
        Assert.Empty(BaselineComparer.Compare(baseline, TestData.Report(Dns("example.test. 20 IN A 192.0.2.1"))).Changes);
        Assert.Contains(BaselineComparer.Compare(baseline, TestData.Report(Dns("example.test. 20 IN A 192.0.2.2"))).Changes, c => c.Kind == "dns-changed");
    }
    [Fact]
    public void HtmlEscapesUntrustedEvidenceAndRejectsJavascriptReference()
    {
        var report = TestData.Report(Open) with
        {
            Findings = [new("CUSTOM_X", Severity.High, "<script>alert(1)</script>", "<img src=x>", "Fix", [TestData.E("payload", "<svg onload=alert(1)>")], "javascript:alert(1)")]
        };
        var html = ReportExporter.Html(report);
        Assert.DoesNotContain("<script>", html); Assert.DoesNotContain("<svg", html);
        Assert.Contains("&lt;script&gt;", html); Assert.DoesNotContain("href='javascript:", html);
        Assert.Contains("Content-Security-Policy", html);
    }
    [Fact]
    public async Task HistoryRoundTripsAndIsolatesClientPaths()
    {
        var root = Path.Combine(Path.GetTempPath(), "sentrynet-tests-" + Guid.NewGuid());
        try
        {
            var store = new FileReportStore(root);
            var report = TestData.Report(Open) with { Options = TestData.Options() with { Client = "../../client" } };
            Assert.StartsWith(Path.GetFullPath(root) + Path.DirectorySeparatorChar, store.ClientDirectory(report.Options.Client));
            await store.SaveAsync(report);
            var loaded = await store.LoadAsync(store.ReportPath(report));
            Assert.Equal(report.Id, loaded.Id); Assert.Equal(report.Findings[0].RuleId, loaded.Findings[0].RuleId);
            Assert.Single(await store.ListAsync(report.Options.Client)); Assert.Empty(await store.ListAsync("other"));
            Assert.Empty(Directory.EnumerateFiles(root, "*.tmp", SearchOption.AllDirectories));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }
    [Fact]
    public async Task SarifIncludesMachineReadableSeverityAndFingerprint()
    {
        var file = Path.Combine(Path.GetTempPath(), "sentrynet-tests-" + Guid.NewGuid() + ".sarif");
        try
        {
            await ReportExporter.SarifAsync(TestData.Report(Open), file);
            using var document = JsonDocument.Parse(await File.ReadAllTextAsync(file));
            Assert.Equal("2.1.0", document.RootElement.GetProperty("version").GetString());
            var finding = document.RootElement.GetProperty("runs")[0].GetProperty("results")[0];
            Assert.Equal("error", finding.GetProperty("level").GetString());
            Assert.True(finding.TryGetProperty("partialFingerprints", out _));
        }
        finally { File.Delete(file); }
    }
}
