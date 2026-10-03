using SentryNet.Core;

namespace SentryNet.SamplePlugin;

public sealed class CompanyPolicyPlugin : ISentryNetPlugin
{
    public string Name => "Example company header policy";
    public string Version => "1.0.0";
    public IEnumerable<IScanner> CreateScanners() => [];
    public IEnumerable<IRule> CreateRules() => [new PoweredByRule()];
}
public sealed class PoweredByRule : IRule
{
    public string Id => "CUSTOM_POWERED_BY";
    public string PolicySignature => "example-company/powered-by/1";
    public IEnumerable<Finding> Evaluate(IReadOnlyList<ProbeResult> probes)
    {
        foreach (var probe in probes.Where(p => p.Scanner == "http"))
            foreach (var evidence in probe.Evidence.Where(e => e.Key.EndsWith(".header.x-powered-by", StringComparison.Ordinal)))
                yield return new(Id, Severity.Low, "Company policy: technology disclosure header", probe.Asset + "/" + evidence.Key,
                    "Remove X-Powered-By if operational requirements permit it.", [evidence], "https://owasp.org/www-project-web-security-testing-guide/");
    }
}
