using SentryNet.Core;

namespace SentryNet.Cli;

public static class DemoReport
{
    public static ScanReport Create()
    {
        var time = new DateTimeOffset(2026, 1, 15, 12, 0, 0, TimeSpan.Zero);
        Evidence E(string key, string value, string scanner) => new(key, value, scanner, time);
        ProbeResult[] probes =
        [
            new("tcp", "192.0.2.10", ProbeStatus.Complete, [E("tcp.23", "open", "tcp"), E("tcp.443", "open", "tcp")], [new(23, "tcp", "telnet"), new(443, "tcp", "https")]),
            new("http", "192.0.2.10", ProbeStatus.Complete, [E("http.443.url", "https://portal.example.test/", "http"), E("http.443.status", "200", "http"), E("http.443.header.server", "ExampleServer/1.0", "http"), E("http.443.header.set-cookie", "session=<redacted>; Path=/; HttpOnly", "http")], []),
            new("tls", "192.0.2.10", ProbeStatus.Complete, [E("tls.443.policyErrors", "RemoteCertificateChainErrors", "tls"), E("tls.443.notAfter", time.AddDays(12).ToString("O"), "tls"), E("tls.443.protocol", "Tls12", "tls")], [])
        ];
        return new("1.0", Guid.Parse("8d6688a2-a4e0-4dc1-a2db-e1049c643784"), time, time.AddSeconds(5),
            new() { Targets = ["portal.example.test"], Scope = ["portal.example.test"], Client = "Example Consulting / synthetic demo", Engagement = "Offline demonstration", Authorized = true, AuthorizationReference = "SYNTHETIC DATA — no active scan", Ports = [23, 443], Scanners = ["tcp", "http", "tls"] },
            [new("portal.example.test", "192.0.2.10")], probes, new BuiltinRules().Evaluate(probes).OrderByDescending(f => f.Severity).ToArray(), "demo-policy-v1");
    }
}
