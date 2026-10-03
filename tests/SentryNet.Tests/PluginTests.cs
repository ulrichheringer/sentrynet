using SentryNet.Core;
using SentryNet.SamplePlugin;
using SentryNet.Scanners;

namespace SentryNet.Tests;

public sealed class PluginTests
{
    [Fact]
    public void SamplePluginOnlyEvaluatesObservedHeaders()
    {
        var plugin = new CompanyPolicyPlugin(); Assert.Empty(plugin.CreateScanners());
        var rule = Assert.Single(plugin.CreateRules());
        Assert.Empty(rule.Evaluate([new("http", "127.0.0.1", ProbeStatus.Complete, [], [])]));
        var finding = Assert.Single(rule.Evaluate([new("http", "127.0.0.1", ProbeStatus.Complete, [TestData.E("http.443.header.x-powered-by", "Example")], [])]));
        Assert.Equal("CUSTOM_POWERED_BY", finding.RuleId); Assert.NotEmpty(rule.PolicySignature);
    }
    [Fact]
    public async Task CliLoadsExplicitPluginEntryPoint()
    {
        var cli = typeof(SentryNet.Cli.CliApplication).Assembly.Location;
        var plugin = typeof(CompanyPolicyPlugin).Assembly.Location;
        var result = await new ProcessRunner().RunAsync("dotnet", [cli, "plan", "--targets", "127.0.0.1", "--scope", "127.0.0.1", "--plugin", plugin], TimeSpan.FromSeconds(15), default);
        Assert.Equal(0, result.ExitCode); Assert.Contains("Example company header policy", result.Stderr); Assert.Contains("offline-plan", result.Stdout);
    }
}
