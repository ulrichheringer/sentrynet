using SentryNet.Core;

namespace SentryNet.Tests;

public sealed class RuleTests
{
    [Fact]
    public void MissingEvidenceDoesNotCreateMissingHeaderFindings()
    {
        var probe = new ProbeResult("http", "127.0.0.1", ProbeStatus.Failed, [], [], "unreachable");
        Assert.Empty(new BuiltinRules().Evaluate([probe]));
    }
    [Fact]
    public void HstsAppliesOnlyToObservedHttps()
    {
        var http = new ProbeResult("http", "127.0.0.1", ProbeStatus.Complete,
            [TestData.E("http.80.url", "http://example.test/"), TestData.E("http.80.status", "301")], []);
        Assert.DoesNotContain(new BuiltinRules().Evaluate([http]), f => f.RuleId is "HTTP001" or "HTTP002");
        var https = http with { Evidence = [TestData.E("http.443.url", "https://example.test/"), TestData.E("http.443.status", "200")] };
        Assert.Contains(new BuiltinRules().Evaluate([https]), f => f.RuleId == "HTTP002");
    }
    [Fact]
    public void CertificateExpiryUsesObservationTime()
    {
        var probe = new ProbeResult("tls", "127.0.0.1", ProbeStatus.Complete,
            [TestData.E("tls.443.policyErrors", "None", "tls"), TestData.E("tls.443.notAfter", "2026-01-15T00:00:00Z", "tls")], []);
        var finding = Assert.Single(new BuiltinRules().Evaluate([probe]));
        Assert.Equal("TLS003", finding.RuleId);
    }
    [Theory]
    [InlineData("2025-12-31T00:00:00Z", "TLS002")]
    [InlineData("2026-01-20T00:00:00Z", "TLS003")]
    public void ClassifiesExpiry(string date, string expected)
    {
        var probe = new ProbeResult("tls", "127.0.0.1", ProbeStatus.Complete,
            [TestData.E("tls.443.policyErrors", "None", "tls"), TestData.E("tls.443.notAfter", date, "tls")], []);
        Assert.Equal(expected, Assert.Single(new BuiltinRules().Evaluate([probe])).RuleId);
    }
    [Fact]
    public void SecureCookieFlagsMustBeAttributes()
    {
        var probe = new ProbeResult("http", "127.0.0.1", ProbeStatus.Complete,
            [TestData.E("http.443.url", "https://example.test/"), TestData.E("http.443.status", "200"), TestData.E("http.443.header.set-cookie", "SecureSession=<redacted>; HttpOnly; SameSite=Lax")], []);
        Assert.Contains(new BuiltinRules().Evaluate([probe]), f => f.RuleId == "HTTP008");
        Assert.DoesNotContain(new BuiltinRules().Evaluate([probe]), f => f.RuleId is "HTTP009" or "HTTP011");
    }
    [Fact]
    public void DnsFailuresDoNotInventAbsentRecords()
    {
        Assert.Empty(new BuiltinRules().Evaluate([new("dig", "127.0.0.1", ProbeStatus.Failed, [], [], "SERVFAIL")]));
    }
    [Theory]
    [InlineData("+all", true)]
    [InlineData("all", true)]
    [InlineData("-all", false)]
    [InlineData("~all", false)]
    [InlineData("?all", false)]
    public void DetectsSpfPermissivePolicy(string ending, bool expected)
    {
        var probe = new ProbeResult("dig", "127.0.0.1", ProbeStatus.Complete,
            [TestData.E("dns.record.mx", "example.test. 300 IN MX 10 mail.example.test.", "dig"), TestData.E("dns.record.txt", $"example.test. 300 IN TXT \"v=spf1 {ending}\"", "dig")], []);
        Assert.Equal(expected, new BuiltinRules().Evaluate([probe]).Any(f => f.RuleId == "DNS003"));
    }
    [Fact]
    public void NullMxDoesNotRequireSpfOrDmarc()
    {
        var probe = new ProbeResult("dig", "127.0.0.1", ProbeStatus.Complete,
            [TestData.E("dns.record.mx", "example.test. 300 IN MX 0 .", "dig"), TestData.E("dns.record.txt", "", "dig"), TestData.E("dns.record.dmarc", "", "dig")], []);
        Assert.Empty(new BuiltinRules().Evaluate([probe]));
    }
    [Fact]
    public void CustomRulesRequireObservedEvidence()
    {
        var rule = new JsonRuleSet([new("CUSTOM_SERVER", "http", "http.80.header.server", "contains", "legacy", Severity.Medium, "Legacy server", "Upgrade")]);
        Assert.Empty(rule.Evaluate([new("http", "127.0.0.1", ProbeStatus.Failed, [], [])]));
        Assert.Single(rule.Evaluate([new("http", "127.0.0.1", ProbeStatus.Complete, [TestData.E("http.80.header.server", "legacy/1")], [])]));
    }
    [Fact]
    public void RejectsUnsupportedCustomOperator() => Assert.Throws<ArgumentException>(() => new JsonRuleSet([new("CUSTOM_X", "tcp", "tcp.80", "execute", "", Severity.High, "Title", "Fix")]));
}
