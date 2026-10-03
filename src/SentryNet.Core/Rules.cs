using System.Globalization;
using System.Net.Security;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SentryNet.Core;

public sealed record RuleDescriptor(string Id, Severity Severity, string Title, string Recommendation, string Reference);
public sealed class BuiltinRules : IRule
{
    public string Id => "builtin";
    public string PolicySignature => JsonSerializer.Serialize(Catalog, JsonDefaults.Options);
    public static IReadOnlyList<RuleDescriptor> Catalog { get; } =
    [
        new("NET001", Severity.High, "Telnet service exposed", "Disable Telnet and use SSH with strong authentication.", "https://www.cisa.gov/news-events/alerts/2017/01/03/securing-network-infrastructure-devices"),
        new("NET002", Severity.Medium, "FTP service exposed", "Use SFTP or enforce FTPS; verify anonymous access manually within scope.", "https://www.rfc-editor.org/rfc/rfc2577"),
        new("NET003", Severity.Medium, "Remote administration service exposed", "Restrict RDP/SSH to approved management networks; require MFA where supported.", "https://www.cisa.gov/stopransomware/ransomware-guide"),
        new("NET004", Severity.Medium, "Database service exposed", "Restrict network access to application hosts and require authentication and encryption.", "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html"),
        new("NET005", Severity.Medium, "SMB or NetBIOS service exposed", "Restrict access to trusted networks, disable SMBv1, and verify signing requirements manually.", "https://www.cisa.gov/stopransomware/ransomware-guide"),
        new("NET006", Severity.Low, "Cleartext mail service exposed", "Require STARTTLS or TLS and verify downgrade protections. Port exposure alone does not establish plaintext authentication.", "https://www.rfc-editor.org/rfc/rfc8314"),
        new("HTTP001", Severity.Medium, "HTTP endpoint reachable without TLS", "Redirect HTTP to an HTTPS endpoint and avoid credentials over HTTP.", "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"),
        new("HTTP002", Severity.Medium, "Strict-Transport-Security missing", "Configure HSTS after validating complete HTTPS support; assess subdomains before enabling includeSubDomains.", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"),
        new("HTTP003", Severity.Low, "Content-Security-Policy missing", "Define an application-specific CSP and test in report-only mode first.", "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"),
        new("HTTP004", Severity.Low, "X-Content-Type-Options missing or invalid", "Send X-Content-Type-Options: nosniff with correct content types.", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"),
        new("HTTP005", Severity.Low, "Clickjacking protection missing", "Use CSP frame-ancestors or X-Frame-Options, aligned with embedding requirements.", "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"),
        new("HTTP006", Severity.Info, "Server technology disclosed", "Reduce unnecessary server/version headers where practical; prioritize patching.", "https://owasp.org/www-project-web-security-testing-guide/"),
        new("HTTP007", Severity.Low, "Wildcard CORS policy", "Allow only required origins for sensitive resources; validate whether the resource is intentionally public.", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"),
        new("HTTP008", Severity.Medium, "Cookie missing Secure flag", "Set Secure for cookies intended for HTTPS, especially session cookies.", "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"),
        new("HTTP009", Severity.Low, "Cookie missing HttpOnly flag", "Set HttpOnly on session cookies unless application JavaScript must access the cookie.", "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"),
        new("HTTP010", Severity.Low, "Referrer-Policy missing", "Set an appropriate Referrer-Policy such as strict-origin-when-cross-origin.", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"),
        new("HTTP011", Severity.Low, "Cookie missing SameSite attribute", "Set SameSite=Lax or Strict when appropriate; SameSite=None requires Secure.", "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"),
        new("HTTP012", Severity.Medium, "HTTPS redirects to cleartext HTTP", "Keep redirects on HTTPS and review canonical URL configuration.", "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"),
        new("TLS001", Severity.High, "TLS certificate validation failed", "Fix trust chain, hostname mismatch or invalid validity dates. Confirm trust against the client's intended trust store.", "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"),
        new("TLS002", Severity.High, "TLS certificate expired", "Renew and deploy the certificate with its complete chain.", "https://www.rfc-editor.org/rfc/rfc5280"),
        new("TLS003", Severity.Medium, "TLS certificate expires within 30 days", "Renew the certificate and automate renewal monitoring.", "https://www.rfc-editor.org/rfc/rfc5280"),
        new("TLS004", Severity.High, "TLS certificate not yet valid", "Check certificate validity and system clock before deploying a replacement.", "https://www.rfc-editor.org/rfc/rfc5280"),
        new("TLS005", Severity.Medium, "RSA key smaller than 2048 bits", "Deploy a certificate with RSA >= 2048 bits or a suitable modern elliptic curve.", "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"),
        new("TLS006", Severity.High, "Weak certificate signature", "Replace certificates signed with MD5 or SHA-1.", "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"),
        new("TLS007", Severity.High, "Legacy TLS protocol negotiated", "Require TLS 1.2 or TLS 1.3. This observation does not enumerate all accepted protocol versions.", "https://www.rfc-editor.org/rfc/rfc8996"),
        new("DNS001", Severity.Low, "CAA record absent", "Consider CAA records limiting authorized certificate authorities; confirm domain hierarchy and policy.", "https://www.rfc-editor.org/rfc/rfc8659"),
        new("DNS002", Severity.Medium, "SPF record absent on mail-enabled domain", "Publish an SPF policy listing authorized mail senders, with a deliberate failure policy.", "https://www.rfc-editor.org/rfc/rfc7208"),
        new("DNS003", Severity.High, "SPF policy permits every sender", "Remove +all and restrict authorized senders after validating mail flows.", "https://www.rfc-editor.org/rfc/rfc7208"),
        new("DNS004", Severity.Medium, "DMARC record absent on mail-enabled domain", "Deploy DMARC with reporting and phase enforcement in after validating SPF/DKIM alignment.", "https://www.rfc-editor.org/rfc/rfc7489"),
        new("DNS005", Severity.Low, "DMARC policy is monitoring only", "Review aggregate reports and progressively enforce quarantine or reject.", "https://www.rfc-editor.org/rfc/rfc7489")
    ];
    private static Finding F(string id, string asset, params Evidence[] evidence)
    {
        var rule = Catalog.Single(r => r.Id == id);
        return new(id, rule.Severity, rule.Title, asset, rule.Recommendation, evidence, rule.Reference);
    }
    public IEnumerable<Finding> Evaluate(IReadOnlyList<ProbeResult> probes)
    {
        foreach (var probe in probes)
        {
            foreach (var service in probe.Services.Where(s => s.Protocol == "tcp"))
            {
                var id = service.Port switch { 23 => "NET001", 21 => "NET002", 22 or 3389 => "NET003",
                    1433 or 3306 or 5432 or 6379 or 27017 => "NET004", 139 or 445 => "NET005", 25 or 110 or 143 => "NET006", _ => null };
                if (id is not null) yield return F(id, $"{probe.Asset}/tcp/{service.Port}",
                    new Evidence("service", $"{service.Name} {service.Product} {service.Version}".Trim(), probe.Scanner, probe.Evidence.FirstOrDefault()?.ObservedAt ?? DateTimeOffset.UtcNow));
            }
            if (probe.Scanner == "http")
            {
                foreach (var status in probe.Evidence.Where(e => e.Key.EndsWith(".status", StringComparison.Ordinal)))
                {
                    var prefix = status.Key[..^6];
                    Evidence? Get(string key) => probe.Evidence.FirstOrDefault(e => e.Key == prefix + key);
                    var url = Get("url"); if (url is null) continue;
                    var asset = probe.Asset + "/" + url.Value;
                    bool Has(string name) => !string.IsNullOrWhiteSpace(Get("header." + name)?.Value);
                    var https = url.Value.StartsWith("https:", StringComparison.Ordinal);
                    if (!https && int.TryParse(status.Value, out var code) && code is not (>= 300 and <= 399)) yield return F("HTTP001", asset, url, status);
                    if (https && !Has("strict-transport-security")) yield return F("HTTP002", asset, url, status);
                    if (!Has("content-security-policy")) yield return F("HTTP003", asset, url, status);
                    if (!string.Equals(Get("header.x-content-type-options")?.Value, "nosniff", StringComparison.OrdinalIgnoreCase)) yield return F("HTTP004", asset, url, status);
                    if (!Has("x-frame-options") && !(Get("header.content-security-policy")?.Value.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase) ?? false)) yield return F("HTTP005", asset, url, status);
                    if (Get("header.server") is { } server) yield return F("HTTP006", asset, server);
                    if (Get("header.x-powered-by") is { } powered) yield return F("HTTP006", asset, powered);
                    if (Get("header.access-control-allow-origin") is { Value: "*" } cors) yield return F("HTTP007", asset, cors);
                    if (!Has("referrer-policy")) yield return F("HTTP010", asset, url, status);
                    if (https && Get("header.location") is { } location && location.Value.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) yield return F("HTTP012", asset, location);
                    if (Get("header.set-cookie") is { } cookies)
                    {
                        var list = cookies.Value.Split(" | ");
                        bool AllFlag(string flag) => list.All(cookie => cookie.Split(';').Skip(1).Any(p => p.Trim().Equals(flag, StringComparison.OrdinalIgnoreCase)));
                        if (!AllFlag("Secure")) yield return F("HTTP008", asset, cookies);
                        if (!AllFlag("HttpOnly")) yield return F("HTTP009", asset, cookies);
                        if (list.Any(cookie => !cookie.Split(';').Skip(1).Any(p => p.Trim().StartsWith("SameSite=", StringComparison.OrdinalIgnoreCase)))) yield return F("HTTP011", asset, cookies);
                    }
                }
            }
            if (probe.Scanner == "tls")
            {
                foreach (var policy in probe.Evidence.Where(e => e.Key.EndsWith(".policyErrors", StringComparison.Ordinal)))
                {
                    var prefix = policy.Key[..^12]; var asset = probe.Asset + "/" + prefix.TrimEnd('.');
                    Evidence? Get(string key) => probe.Evidence.FirstOrDefault(e => e.Key == prefix + key);
                    if (policy.Value != SslPolicyErrors.None.ToString()) yield return F("TLS001", asset, policy);
                    var observed = policy.ObservedAt;
                    if (Get("notAfter") is { } expires && DateTimeOffset.TryParse(expires.Value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var end))
                    {
                        if (end < observed) yield return F("TLS002", asset, expires);
                        else if (end < observed.AddDays(30)) yield return F("TLS003", asset, expires);
                    }
                    if (Get("notBefore") is { } begins && DateTimeOffset.TryParse(begins.Value, out var start) && start > observed) yield return F("TLS004", asset, begins);
                    if (Get("rsaBits") is { } bits && int.TryParse(bits.Value, out var size) && size < 2048) yield return F("TLS005", asset, bits);
                    if (Get("signature") is { } signature && (signature.Value.Contains("sha1", StringComparison.OrdinalIgnoreCase) || signature.Value.Contains("md5", StringComparison.OrdinalIgnoreCase))) yield return F("TLS006", asset, signature);
                    if (Get("protocol") is { } protocol && protocol.Value is not ("Tls12" or "Tls13")) yield return F("TLS007", asset, protocol);
                }
            }
            if (probe.Scanner == "dig")
            {
                Evidence? Get(string key) => probe.Evidence.FirstOrDefault(e => e.Key == "dns.record." + key);
                var name = probe.Evidence.FirstOrDefault(e => e.Key == "dns.query.a")?.Value ?? probe.Asset;
                if (Get("caa") is { Value.Length: 0 } caa) yield return F("DNS001", name, caa);
                if (Get("mx") is not { Value.Length: > 0 }) continue;
                if (Get("txt") is { } txt)
                {
                    if (!txt.Value.Contains("v=spf1", StringComparison.OrdinalIgnoreCase)) yield return F("DNS002", name, txt);
                    if (Regex.IsMatch(txt.Value, @"(?:\s|""|^)\+?all(?:\s|""|$)", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1))) yield return F("DNS003", name, txt);
                }
                if (Get("dmarc") is { } dmarc)
                {
                    if (!dmarc.Value.Contains("v=DMARC1", StringComparison.OrdinalIgnoreCase)) yield return F("DNS004", name, dmarc);
                    else if (Regex.IsMatch(dmarc.Value, @"\bp\s*=\s*none\b", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1))) yield return F("DNS005", name, dmarc);
                }
            }
        }
    }
}
public sealed record DeclarativeRule(string Id, string Scanner, string EvidenceKey, string Operator, string Value,
    Severity Severity, string Title, string Recommendation, string? Reference = null);
public sealed class JsonRuleSet : IRule
{
    public string Id => "custom";
    public string PolicySignature => JsonSerializer.Serialize(rules, JsonDefaults.Options);
    private readonly DeclarativeRule[] rules;
    public JsonRuleSet(IEnumerable<DeclarativeRule> definitions)
    {
        rules = definitions.ToArray();
        if (rules.Length > 1000 || rules.Select(r => r.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count() != rules.Length)
            throw new ArgumentException("Custom rules must have unique IDs and at most 1000 definitions.");
        foreach (var r in rules)
            if (!r.Id.StartsWith("CUSTOM_", StringComparison.Ordinal) || string.IsNullOrWhiteSpace(r.Title) || string.IsNullOrWhiteSpace(r.Recommendation) ||
                r.Operator is not ("equals" or "contains" or "notEquals")) throw new ArgumentException($"Invalid custom rule: {r.Id}");
    }
    public static async Task<JsonRuleSet> LoadAsync(string path, CancellationToken ct = default)
    {
        if (new FileInfo(path).Length > 1024 * 1024) throw new ArgumentException("Rules file exceeds 1 MiB.");
        using var file = File.OpenRead(path);
        return new(await JsonSerializer.DeserializeAsync<DeclarativeRule[]>(file, JsonDefaults.Options, ct) ?? []);
    }
    public IEnumerable<Finding> Evaluate(IReadOnlyList<ProbeResult> probes)
    {
        foreach (var rule in rules)
        foreach (var probe in probes.Where(p => p.Scanner.Equals(rule.Scanner, StringComparison.OrdinalIgnoreCase)))
        foreach (var evidence in probe.Evidence.Where(e => e.Key.Equals(rule.EvidenceKey, StringComparison.OrdinalIgnoreCase)))
        {
            var matches = rule.Operator switch
            {
                "equals" => evidence.Value.Equals(rule.Value, StringComparison.OrdinalIgnoreCase),
                "notEquals" => !evidence.Value.Equals(rule.Value, StringComparison.OrdinalIgnoreCase),
                "contains" => evidence.Value.Contains(rule.Value, StringComparison.OrdinalIgnoreCase), _ => false
            };
            if (matches) yield return new(rule.Id, rule.Severity, rule.Title, probe.Asset + "/" + evidence.Key, rule.Recommendation, [evidence], rule.Reference);
        }
    }
}
