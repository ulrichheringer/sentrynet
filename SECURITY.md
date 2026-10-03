# Security policy

SentryNet is a defensive auditing tool. Active scans are restricted to operator-declared authorized scope, but the CLI cannot establish legal ownership or validate written authorization.

Report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/ulrichheringer/sentrynet/security/advisories/new) when available. If the repository has not enabled that channel, contact the maintainer using the contact method on their GitHub profile and request a private channel. Do not publish exploit details, client reports, authorization documents, credentials, or internal addresses in public issues.

The initial supported development line is 0.1.x. Update the .NET runtime and dependencies with security fixes. The current .NET 8 target requires migration before its vendor support ends; see the roadmap.

Plugins execute trusted code with the operator's privileges. They are not sandboxed and can violate scanner conventions. Load only reviewed assemblies, and protect config, rules, output directories, and local history with OS access controls. Multi-client history folders are organizational separation, not a tenant security boundary.
