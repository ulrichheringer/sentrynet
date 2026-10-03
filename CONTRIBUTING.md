# Contributing

Use .NET 8 SDK and run `dotnet build -c Release`, `dotnet test -c Release`, and `dotnet format --verify-no-changes` before opening a pull request. Keep commits focused and describe the trigger, resulting behavior, and validation.

Network tests must create their own loopback fixtures; never depend on public hosts or scan contributor networks. Preserve explicit authorization, scope checks, pinned addresses, bounded concurrency, cancellation, and honest handling of incomplete evidence. Scanner and rule additions need meaningful tests for false positives and failure cases.

Do not add exploits, password guessing, broad auto-discovery, arbitrary shell execution, or a plugin auto-install flow. Add scanners through `IScanner`, rules through `IRule`, and document coverage and limitations. Metadata and recommendations must reflect evidence rather than infer a CVE from an unverified version string.

Report rendering must HTML-encode all external values. Avoid logging credentials, cookie values, or sensitive response bodies. Never commit real customer reports, internal target lists, secrets, or authorization documents.

When Windows application-control policies block xUnit discovery, do not treat a zero exit code with zero tests as validation. Run the same suite in the documented Linux Docker workflow or a permitted CI runner. Do not change security settings to run the tests.
