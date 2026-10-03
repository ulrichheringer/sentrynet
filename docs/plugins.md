# Plugins and custom rules

Start with JSON rules when a policy can be expressed using observed evidence. Supported operators are case-insensitive `equals`, `notEquals` and `contains`. Missing observations never satisfy a rule; `notEquals` requires the evidence key to exist. IDs must start with `CUSTOM_`, be unique inside the file, and include a title and recommendation. Regex or command execution is not available. See [samples/rules.json](../samples/rules.json).

For scanners or richer rules, reference `SentryNet.Core` in a .NET 8 class library and implement `ISentryNetPlugin`. A parameterless plugin entry point returns `IScanner` and `IRule` instances; dependencies may be constructed inside the plugin. Every scanner must honor the supplied pinned target, options and cancellation token. Return failures as collection gaps and include timestamped evidence. Never resolve a different connection target or expand scope on your own.

```csharp
public sealed class CompanyPlugin : ISentryNetPlugin
{
    public string Name => "Company policy";
    public string Version => "1.0.0";
    public IEnumerable<IScanner> CreateScanners() => [];
    public IEnumerable<IRule> CreateRules() => [new CompanyRule()];
}
```

Build the working example:

```sh
dotnet build samples/SentryNet.SamplePlugin -c Release
dotnet run --project src/SentryNet.Cli -- plan --config samples/local.json --plugin samples/SentryNet.SamplePlugin/bin/Release/net8.0/SentryNet.SamplePlugin.dll
```

Add `--plugin` to an authorized scan to evaluate the policy. The example has no scanner and only reviews collected headers. `PolicySignature` must identify rule behavior/configuration so baseline comparisons cannot incorrectly treat changed rules as remediation.

Plugins execute with full process privileges. Explicit loading is deliberate, not a sandbox or a trust verifier. The initial loader shares the host assembly context and does not resolve arbitrary private dependency graphs or unload plugins. Native dependency isolation, signing and an authenticated plugin registry are future work.
