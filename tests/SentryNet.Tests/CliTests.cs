using SentryNet.Cli;
using SentryNet.Core;

namespace SentryNet.Tests;

public sealed class CliTests
{
    [Theory]
    [InlineData("22,80,443", 3)]
    [InlineData("80-82,81", 3)]
    [InlineData("65535", 1)]
    public void ParsesPortRanges(string input, int count) => Assert.Equal(count, Arguments.ParsePorts(input).Length);
    [Theory]
    [InlineData("0")]
    [InlineData("65536")]
    [InlineData("100-1")]
    [InlineData("1-65535")]
    [InlineData("1-2-3")]
    public void RejectsInvalidOrExcessivePorts(string input) => Assert.Throws<ArgumentException>(() => Arguments.ParsePorts(input));
    [Fact]
    public void RejectsUnknownMissingAndDuplicateOptions()
    {
        Assert.Throws<ArgumentException>(() => new Arguments(["scan", "--oops"]));
        Assert.Throws<ArgumentException>(() => new Arguments(["scan", "--targets"]));
        Assert.Throws<ArgumentException>(() => new Arguments(["scan", "--targets", "127.0.0.1", "--targets", "127.0.0.2"]));
    }
    [Fact]
    public void ConfigCannotSilentlyAuthorizeExecution()
    {
        var args = new Arguments(["scan"]);
        Assert.False(args.Apply(TestData.Options()).Authorized);
        Assert.True(new Arguments(["scan", "--authorized"]).Apply(TestData.Options()).Authorized);
    }
    [Fact]
    public void ExplicitOptionsOverrideProfileAndConfig()
    {
        var options = new Arguments(["scan", "--profile", "quick", "--ports", "12345", "--scanners", "tls", "--severity", "TLS001=Low"]).Apply(TestData.Options());
        Assert.Equal([12345], options.Ports); Assert.Equal(["tls"], options.Scanners); Assert.Equal(Severity.Low, options.SeverityOverrides["TLS001"]);
    }
    [Fact]
    public void DemoHasDeterministicSyntheticData()
    {
        var report = DemoReport.Create();
        Assert.Contains(report.Findings, f => f.RuleId == "NET001"); Assert.Contains(report.Findings, f => f.RuleId == "TLS003");
        Assert.Equal("192.0.2.10", Assert.Single(report.Targets).Address);
    }
}
