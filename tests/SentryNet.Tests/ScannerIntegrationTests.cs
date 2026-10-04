using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SentryNet.Core;
using SentryNet.Scanners;

namespace SentryNet.Tests;

public sealed class ScannerIntegrationTests
{
    [Fact]
    public async Task TcpInventoriesOwnedLoopbackListener()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var result = await new TcpScanner().ScanAsync(new("127.0.0.1", "127.0.0.1"), TestData.Options() with { Ports = [port] }, default);
        Assert.Equal(port, Assert.Single(result.Services).Port); Assert.Equal(ProbeStatus.Complete, result.Status);
    }
    [Fact]
    public async Task HttpPinsAddressPreservesHostAndDoesNotFollowRedirect()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var server = Task.Run(async () =>
        {
            using var socket = await listener.AcceptTcpClientAsync(deadline.Token);
            using var reader = new StreamReader(socket.GetStream(), Encoding.ASCII, false, leaveOpen: true);
            var lines = new List<string>(); string? line;
            while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync(deadline.Token))) lines.Add(line);
            var response = "HTTP/1.1 302 Found\r\nLocation: http://unauthorized.example.invalid/\r\nSet-Cookie: token=secret-value; HttpOnly; SameSite=Lax\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            await socket.GetStream().WriteAsync(Encoding.ASCII.GetBytes(response), deadline.Token);
            return lines;
        }, deadline.Token);
        var result = await new HttpScanner().ScanAsync(new("authorized.example.invalid", "127.0.0.1"), TestData.Options() with { Ports = [port], HttpPorts = [port] }, deadline.Token);
        var lines = await server;
        Assert.Contains(lines, line => line == $"Host: authorized.example.invalid:{port}");
        Assert.Equal(ProbeStatus.Complete, result.Status);
        Assert.Contains(result.Evidence, e => e.Key.EndsWith(".status", StringComparison.Ordinal) && e.Value == "302");
        Assert.DoesNotContain(result.Evidence, e => e.Value.Contains("secret-value", StringComparison.Ordinal));
        Assert.Contains(result.Evidence, e => e.Value.Contains("<redacted>", StringComparison.Ordinal));
        Assert.False(listener.Pending());
    }
    [Fact]
    public async Task TlsInspectsSelfSignedCertificateWithoutApplicationPayload()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var sans = new SubjectAlternativeNameBuilder(); sans.AddDnsName("localhost"); request.CertificateExtensions.Add(sans.Build());
        using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(10));
        // Schannel server credentials require a key container rather than an ephemeral generated key.
        // This does not install the certificate into a trust store; disposal removes the temporary key.
        using var certificate = new X509Certificate2(created.Export(X509ContentType.Pfx), (string?)null,
            OperatingSystem.IsWindows() ? X509KeyStorageFlags.UserKeySet : X509KeyStorageFlags.EphemeralKeySet);
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var server = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(deadline.Token);
            using var ssl = new SslStream(client.GetStream());
            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = certificate, EnabledSslProtocols = SslProtocols.Tls12 }, deadline.Token);
            try { return await ssl.ReadAsync(new byte[16], deadline.Token); }
            catch (IOException) { return 0; } // A close/reset is acceptable; no application data.
        }, deadline.Token);
        var result = await new TlsScanner().ScanAsync(new("localhost", "127.0.0.1"), TestData.Options() with { Ports = [port], TlsPorts = [port] }, deadline.Token);
        var received = await server;
        Assert.True(result.Status == ProbeStatus.Complete, result.Error); Assert.Equal(0, received);
        Assert.Contains(result.Evidence, e => e.Key.EndsWith(".policyErrors", StringComparison.Ordinal) && e.Value.Contains("ChainErrors", StringComparison.Ordinal));
        Assert.Contains(result.Evidence, e => e.Key.EndsWith(".sha256", StringComparison.Ordinal) && e.Value.Length == 64);
        Assert.Contains(new BuiltinRules().Evaluate([result]), f => f.RuleId == "TLS001");
    }
    [Fact]
    public void ParsesNmapXmlWithoutLoadingExternalDtd()
    {
        const string xml = """
            <?xml version="1.0"?><!DOCTYPE nmaprun SYSTEM "file:///nonexistent-secret">
            <nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
            <ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.2"/></port>
            <port protocol="tcp" portid="80"><state state="closed"/></port></ports></host>
            <runstats><finished exit="success"/></runstats></nmaprun>
            """;
        var result = NmapScanner.Parse(xml, "127.0.0.1");
        Assert.Equal(ProbeStatus.Complete, result.Status); Assert.Equal("nginx", Assert.Single(result.Services).Product);
        Assert.Equal(ProbeStatus.Failed, NmapScanner.Parse(xml, "192.0.2.1").Status);
    }
    [Fact]
    public async Task NmapArgumentsAreFixedAndUsePinnedAddress()
    {
        var runner = new CapturingRunner();
        await new NmapScanner(runner).ScanAsync(new("example.test", "192.0.2.10"), TestData.Options(), default);
        Assert.Equal("192.0.2.10", runner.Arguments.Last()); Assert.Contains("-sT", runner.Arguments); Assert.Contains("-n", runner.Arguments);
        Assert.DoesNotContain("--script", runner.Arguments); Assert.DoesNotContain("example.test", runner.Arguments);
    }
    private sealed class CapturingRunner : IProcessRunner
    {
        public IReadOnlyList<string> Arguments = [];
        public Task<ToolResult> RunAsync(string executable, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct)
        { Arguments = arguments; return Task.FromResult(new ToolResult(1, "", "fixture")); }
    }
    [Fact]
    public void DigParserRetainsOnlyRecords() => Assert.Equal("example.test. 30 IN A 192.0.2.1", DigScanner.ParseAnswers(";; status: NOERROR\n; comment\nexample.test. 30 IN A 192.0.2.1\n"));
}
