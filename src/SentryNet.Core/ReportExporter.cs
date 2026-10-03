using System.Net;
using System.Text;
using System.Text.Json;

namespace SentryNet.Core;

public static class ReportExporter
{
    public static Task JsonAsync(ScanReport report, string path, CancellationToken ct = default) =>
        AtomicFile.WriteAsync(path, JsonSerializer.Serialize(report, JsonDefaults.Options), ct);
    public static Task HtmlAsync(ScanReport report, string path, ScanDiff? diff = null, CancellationToken ct = default) =>
        AtomicFile.WriteAsync(path, Html(report, diff), ct);
    public static string Html(ScanReport report, ScanDiff? diff = null)
    {
        static string E(object? value) => WebUtility.HtmlEncode(value?.ToString() ?? "");
        var html = new StringBuilder("""
            <!doctype html><html lang="en"><head><meta charset="utf-8">
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
            <title>SentryNet • Security audit</title><style>
            :root{color-scheme:light;--ink:#162331;--muted:#526170;--line:#d8e0e7;--accent:#087f8c}
            *{box-sizing:border-box}body{margin:0;background:#edf2f5;color:var(--ink);font:15px/1.6 system-ui,sans-serif}
            main{max-width:1160px;margin:32px auto;background:white;padding:48px;border-radius:12px}
            header{border-bottom:3px solid var(--accent);padding-bottom:24px}.brand{font-weight:800;font-size:16px;letter-spacing:3px;color:var(--accent)}
            h1{font-size:36px;line-height:1.2;margin:12px 0}h2{margin-top:36px;font-size:23px}h3{margin:0 0 8px}
            p{margin:8px 0}.muted,small{color:var(--muted)}.metrics{display:flex;gap:12px;flex-wrap:wrap;margin:24px 0}.metric{flex:1;padding:16px;background:#f3f7fa;min-width:140px;border-radius:8px}.metric strong{display:block;font-size:28px}
            table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}th{background:#f3f7fa}
            .finding{border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:6px;margin:16px 0;padding:20px;break-inside:avoid}
            .badge{display:inline-block;padding:3px 9px;border-radius:4px;font-size:12px;font-weight:700;background:#e9eef3;margin-right:8px}
            .Critical,.High{background:#ffe0e3;color:#8c2034}.Medium{background:#fff0cc;color:#805600}.Low{background:#dff0ff;color:#205278}.Info{background:#e4f3f0;color:#186556}
            pre,code{font:12px/1.5 ui-monospace,monospace;white-space:pre-wrap;overflow-wrap:anywhere}pre{background:#f6f8fa;padding:10px}
            .notice{background:#fff6dd;border-left:4px solid #c28b18;padding:16px}a{color:#087f8c}footer{margin-top:40px;border-top:1px solid var(--line);padding-top:16px;color:var(--muted);font-size:12px}
            @media(max-width:700px){main{margin:0;padding:20px;border-radius:0}h1{font-size:28px}.metric{min-width:100px}}
            @media print{body{background:white}main{margin:0;padding:0;max-width:none}h2{break-after:avoid}thead{display:table-header-group}a{color:inherit}}
            </style></head><body><main><header><div class="brand">SENTRYNET / DEFENSIVE SECURITY</div><h1>Security audit report</h1>
            """);
        html.Append($"<p>Client: <strong>{E(report.Options.Client)}</strong> · Engagement: {E(report.Options.Engagement)}</p><p class='muted'>{E(report.StartedAt.ToString("u"))} → {E(report.FinishedAt.ToString("u"))} · Scan {E(report.Id)}</p></header>");
        html.Append($"<div class='metrics'><div class='metric'>Resolved targets<strong>{report.Targets.Count}</strong></div><div class='metric'>Open endpoints<strong>{report.Probes.SelectMany(p => p.Services.Select(s => $"{p.Asset}/{s.Protocol}/{s.Port}")).Distinct().Count()}</strong></div><div class='metric'>Findings<strong>{report.Findings.Count}</strong></div><div class='metric'>Incomplete probes<strong>{report.Probes.Count(p => p.Status != ProbeStatus.Complete)}</strong></div></div>");
        html.Append("<h2>Executive assessment</h2><p>Observed exposure and configuration checks identify areas for review. Findings describe evidence at scan time and require context before remediation. Service names inferred from port numbers are not verified products.</p>");
        html.Append($"<p>Collection: <strong>{(report.Complete ? "complete for selected probes" : "partial — review collection gaps")}</strong>. Authorization reference: {E(report.Options.AuthorizationReference)}.</p>");
        html.Append("<table><thead><tr><th>Severity</th><th>Findings</th><th>Interpretation</th></tr></thead><tbody>");
        foreach (var severity in Enum.GetValues<Severity>().Reverse()) html.Append($"<tr><td><span class='badge {severity}'>{severity}</span></td><td>{report.Findings.Count(f => f.Severity == severity)}</td><td>{E(severity switch { Severity.Critical => "Urgent confirmed risk requiring immediate attention", Severity.High => "Prioritize investigation and remediation", Severity.Medium => "Plan remediation after assessing context", Severity.Low => "Hardening opportunity", _ => "Inventory or informational observation" })}</td></tr>");
        html.Append("</tbody></table><h2>Scope and methodology</h2>");
        html.Append($"<p>Authorized scope: <code>{E(string.Join(", ", report.Options.Scope))}</code></p><p>Scanners: {E(string.Join(", ", report.Options.Scanners))}. Ports: {E(string.Join(", ", report.Options.Ports))}. Concurrency: {report.Options.Parallelism}. Timeout: {report.Options.TimeoutMs} ms. Delay: {report.Options.DelayMs} ms.</p>");
        html.Append("<p class='notice'>No exploitation, credential attempts or automatic remediation. HTTP inspects the root path only and never follows redirects. TLS reports negotiated protocol and chain policy; revocation and legacy protocol enumeration are not performed. Missing DNS controls are assessed only when their queries succeeded. Timeouts do not establish closed ports. This report is not a compliance certification.</p>");
        html.Append("<h2>Asset and service inventory</h2><table><thead><tr><th>Host</th><th>Address</th><th>Observed open services</th></tr></thead><tbody>");
        foreach (var target in report.Targets)
        {
            var services = report.Probes.Where(p => p.Asset == target.Address).SelectMany(p => p.Services).Distinct();
            html.Append($"<tr><td>{E(target.Name)}</td><td>{E(target.Address)}</td><td>{E(string.Join("; ", services.Select(s => $"{s.Port}/{s.Protocol} {s.Name} {s.Product} {s.Version}")))}</td></tr>");
        }
        html.Append("</tbody></table><h2>Findings and remediation</h2>");
        if (report.Findings.Count == 0) html.Append("<p>No findings produced by selected rules. Review coverage before drawing conclusions.</p>");
        foreach (var f in report.Findings)
        {
            html.Append($"<article class='finding'><h3><span class='badge {f.Severity}'>{f.Severity}</span>{E(f.RuleId)} · {E(f.Title)}</h3><p><strong>Asset:</strong> {E(f.Asset)}</p><p><strong>Recommendation:</strong> {E(f.Recommendation)}</p><details open><summary>Evidence</summary>");
            foreach (var ev in f.Evidence) html.Append($"<p><strong>{E(ev.Key)}</strong> · {E(ev.Source)} · {E(ev.ObservedAt.ToString("u"))}</p><pre>{E(ev.Value)}</pre>");
            html.Append("</details>");
            if (Uri.TryCreate(f.Reference, UriKind.Absolute, out var reference) && reference.Scheme is "https" or "http")
                html.Append($"<p><a href='{E(reference.AbsoluteUri)}' rel='noreferrer'>Reference guidance</a></p>");
            html.Append("</article>");
        }
        if (diff is not null)
        {
            html.Append("<h2>Changes from baseline</h2>");
            if (diff.Warning is not null) html.Append($"<p class='notice'>{E(diff.Warning)}</p>");
            html.Append($"<p>Baseline: {E(diff.BaselineId)} · {diff.Changes.Count} changes.</p><table><thead><tr><th>Change</th><th>Asset</th><th>Description</th></tr></thead><tbody>");
            foreach (var change in diff.Changes) html.Append($"<tr><td>{E(change.Kind)}</td><td>{E(change.Asset)}</td><td>{E(change.Description)}</td></tr>");
            html.Append("</tbody></table>");
        }
        html.Append("<h2>Collection coverage and gaps</h2><table><thead><tr><th>Scanner</th><th>Asset</th><th>Status</th><th>Details</th></tr></thead><tbody>");
        foreach (var p in report.Probes) html.Append($"<tr><td>{E(p.Scanner)}</td><td>{E(p.Asset)}</td><td>{E(p.Status)}</td><td>{E(p.Error)}</td></tr>");
        html.Append($"</tbody></table><footer>SentryNet 0.1 · Schema {E(report.SchemaVersion)} · Policy {E(report.PolicyFingerprint)}<br>Confidential audit evidence. Store and share according to the engagement's information handling policy.</footer></main></body></html>");
        return html.ToString();
    }
    public static Task SarifAsync(ScanReport report, string path, CancellationToken ct = default)
    {
        var rules = report.Findings.DistinctBy(f => f.RuleId).Select(f => new { id = f.RuleId, name = f.Title, shortDescription = new { text = f.Title }, help = new { text = f.Recommendation } }).ToArray();
        var document = new Dictionary<string, object>
        {
            ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json", ["version"] = "2.1.0",
            ["runs"] = new[] { new {
                tool = new { driver = new { name = "SentryNet", version = "0.1.0", informationUri = "https://github.com/ulrichheringer/sentrynet", rules } },
                results = report.Findings.Select(f => new { ruleId = f.RuleId,
                    level = f.Severity >= Severity.High ? "error" : f.Severity >= Severity.Low ? "warning" : "note",
                    message = new { text = $"{f.Title}: {f.Asset}. {f.Recommendation}" },
                    partialFingerprints = new Dictionary<string, string> { ["sentrynet/v1"] = f.Fingerprint },
                    properties = new { severity = f.Severity.ToString(), asset = f.Asset, evidence = f.Evidence } }).ToArray(),
                invocations = new[] { new { executionSuccessful = report.Complete, startTimeUtc = report.StartedAt.UtcDateTime, endTimeUtc = report.FinishedAt.UtcDateTime } }
            } }
        };
        return AtomicFile.WriteAsync(path, JsonSerializer.Serialize(document, JsonDefaults.Options), ct);
    }
}
