# Roadmap

Implemented in 0.1: local CLI, bounded authorized scans, native TCP/ICMP/DNS/HTTP/TLS, Nmap/dig adapters, rules, evidence, client history, conservative baselines, JSON/HTML/SARIF, plugins and automated loopback tests.

Next priorities:

1. Migrate to a supported successor runtime before .NET 8 support ends on 2026-11-10. Keep Core contracts transport-neutral and test Windows/Linux/macOS.
2. Improve DNS inheritance using a maintained Public Suffix List, explicit DKIM selectors, DNSSEC-aware reporting and stronger SPF/DMARC parsing.
3. Add approved STARTTLS, richer application/service inventory, additional HTTP header validation and explicit opt-in legacy protocol checks with clear probe budgets.
4. Persist cancelled jobs as incomplete records, add resumable work, retention policies, encryption and signed report manifests.
5. Implement durable job storage and an authenticated API, with real tenant isolation and scoped RBAC before adding multiple concurrent users.
6. Build remote agents with signed jobs, mutual authentication, expiry, agent-side scope enforcement, egress policy and secure update distribution.
7. Build a dashboard for inventory, trends, evidence review, suppressions with expiry, engagement workflow and export branding.
8. Add dependency-isolated plugins, signed manifests, compatibility policy and an optional reviewed registry.

These are future capabilities, not features claimed by the current CLI. No automatic exploitation is planned.
