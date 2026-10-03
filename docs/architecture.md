# Architecture

The solution has three production modules and an xUnit test project:

* **SentryNet.Core**: transport-neutral records, authorization/scope, bounded orchestration, rules, baseline, storage, reporting, plugin and future dispatcher contracts. No external package dependencies.
* **SentryNet.Scanners**: native TCP/ICMP/HTTP/TLS/local interface probes, DNS via DnsClient.NET, and Nmap/dig adapters with an injectable process runner.
* **SentryNet.Cli**: strict argument parsing, profiles/config overrides, DI composition, explicit plugin loading, cancellation and exit-code semantics.

The CLI validates configuration and authorization before active work. `ScopePolicy` expands bounded IPv4 CIDRs and resolves authorized names with the OS resolver. The resulting `(Name, Address)` pairs are pinned. The engine parallelizes targets up to the configured limit and executes selected scanners sequentially for each target. Scanners limit individual operations, observe cancellation, and delay between probes. There is no nested unbounded fan-out.

Results contain raw observations, service inventory and a collection status independent of findings. Rules consume only collected evidence. The engine deduplicates findings by rule and asset, applies rule suppression/severity overrides, and records a policy fingerprint. JSON custom rules contribute their full definitions to that fingerprint.

Reports retain scan inputs, resolved targets, individual probe outcomes, evidence with timestamps, findings, recommendation references and a schema version. File history uses atomic same-directory replacement. The client name is hashed for path safety. This local store is replaceable through `IReportStore`; the CLI currently constructs `FileReportStore` to expose local list/path helpers.

Baseline comparison requires equivalent resolved targets, client, engagement, scanners, ports/protocol mappings, DNS configuration, suppression/override policy and rule fingerprint, plus complete collection on both sides. Missing findings/services from non-equivalent or incomplete scans are **unconfirmed**. DNS comparisons remove TTL and normalize record order. Certificate fingerprints capture rotation; version changes capture observed service inventory changes.

`ISentryNetPlugin` supplies scanners and rules from explicitly loaded assemblies. The default assembly context shares the Core contracts with the CLI. The initial loader supports parameterless plugin entry points and dependencies already resolvable by the host; it is not a dependency-isolated plugin marketplace. Plugin `IRule.PolicySignature` must change when rule behavior changes.

`ScanJob`, `AgentIdentity` and `IScanDispatcher` reserve a transport-neutral boundary for future remote execution. They are contracts, not a server or implemented remote agent. A future service must add authentication, job integrity/expiry checks, tenant isolation, independent agent-side scope validation, authorization lifecycle, audit logs and policy distribution before exposing jobs remotely.
