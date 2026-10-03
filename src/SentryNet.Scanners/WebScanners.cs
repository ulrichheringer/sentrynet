using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SentryNet.Core;

namespace SentryNet.Scanners;

public sealed class HttpScanner : IScanner
{
    public string Name => "http";
    public async Task<ProbeResult> ScanAsync(ResolvedTarget target, ScanOptions options, CancellationToken ct)
    {
        var evidence = new List<Evidence>(); var errors = new List<string>();
        var ports = options.Ports.Distinct().Where(options.HttpPorts.Contains).ToArray();
        if (ports.Length == 0) return new(Name, target.Address, ProbeStatus.Skipped, [], [], "No supported HTTP port selected.");
        foreach (var port in ports)
        {
            ct.ThrowIfCancellationRequested();
            var scheme = options.TlsPorts.Contains(port) ? "https" : "http";
            var uri = new UriBuilder(scheme, target.Name, port).Uri;
            using var handler = new SocketsHttpHandler
            {
                AllowAutoRedirect = false, UseProxy = false, UseCookies = false,
                ConnectTimeout = TimeSpan.FromMilliseconds(options.TimeoutMs), MaxResponseHeadersLength = 32,
                ConnectCallback = async (_, token) =>
                {
                    var socket = new Socket(IPAddress.Parse(target.Address).AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    try { await socket.ConnectAsync(new IPEndPoint(IPAddress.Parse(target.Address), port), token); return new NetworkStream(socket, ownsSocket: true); }
                    catch { socket.Dispose(); throw; }
                }
            };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(options.TimeoutMs) };
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.UserAgent.ParseAdd("SentryNet/0.1 defensive-audit");
            try
            {
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
                var prefix = $"http.{port}.";
                evidence.Add(Probe.E(prefix + "url", uri.ToString(), Name));
                evidence.Add(Probe.E(prefix + "status", ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture), Name));
                foreach (var header in response.Headers.Concat(response.Content.Headers))
                {
                    // Cookie values and authentication challenges may contain secrets. Keep only cookie flags/names.
                    var value = header.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase)
                        ? string.Join(" | ", header.Value.Select(RedactCookie)) : string.Join(", ", header.Value);
                    evidence.Add(Probe.E(prefix + "header." + header.Key.ToLowerInvariant(), value, Name));
                }
            }
            catch (Exception ex) when (ex is HttpRequestException || ex is TaskCanceledException && !ct.IsCancellationRequested)
            { errors.Add($"{port}: {ex.Message}"); }
            await Task.Delay(options.DelayMs, ct);
        }
        return new(Name, target.Address, errors.Count > 0 ? ProbeStatus.Failed : ProbeStatus.Complete, evidence, [],
            errors.Count > 0 ? string.Join("; ", errors) : null);
    }
    public static string RedactCookie(string cookie)
    {
        var parts = cookie.Split(';');
        var equals = parts[0].IndexOf('=');
        parts[0] = equals >= 0 ? parts[0][..equals] + "=<redacted>" : "<redacted>";
        return string.Join(";", parts);
    }
}
public sealed class TlsScanner : IScanner
{
    public string Name => "tls";
    public async Task<ProbeResult> ScanAsync(ResolvedTarget target, ScanOptions options, CancellationToken ct)
    {
        var evidence = new List<Evidence>(); var errors = new List<string>();
        var ports = options.Ports.Distinct().Where(options.TlsPorts.Contains).ToArray();
        if (ports.Length == 0) return new(Name, target.Address, ProbeStatus.Skipped, [], [], "No direct TLS port selected (STARTTLS is not implemented).");
        foreach (var port in ports)
        {
            using var timeout = Probe.Timeout(options, ct);
            using var client = new TcpClient(IPAddress.Parse(target.Address).AddressFamily);
            try
            {
                await client.ConnectAsync(IPAddress.Parse(target.Address), port, timeout.Token);
                using var stream = new SslStream(client.GetStream(), false, (_, certificate, chain, policyErrors) =>
                {
                    if (certificate is null) return false;
                    using var cert = new X509Certificate2(certificate);
                    var prefix = $"tls.{port}.";
                    evidence.Add(Probe.E(prefix + "policyErrors", policyErrors.ToString(), Name));
                    evidence.Add(Probe.E(prefix + "subject", cert.Subject, Name));
                    evidence.Add(Probe.E(prefix + "issuer", cert.Issuer, Name));
                    evidence.Add(Probe.E(prefix + "notBefore", cert.NotBefore.ToUniversalTime().ToString("O"), Name));
                    evidence.Add(Probe.E(prefix + "notAfter", cert.NotAfter.ToUniversalTime().ToString("O"), Name));
                    evidence.Add(Probe.E(prefix + "sha256", cert.GetCertHashString(HashAlgorithmName.SHA256), Name));
                    evidence.Add(Probe.E(prefix + "signature", cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value ?? "unknown", Name));
                    evidence.Add(Probe.E(prefix + "san", cert.Extensions["2.5.29.17"]?.Format(false) ?? "", Name));
                    using var rsa = cert.GetRSAPublicKey();
                    if (rsa is not null) evidence.Add(Probe.E(prefix + "rsaBits", rsa.KeySize.ToString(CultureInfo.InvariantCulture), Name));
                    if (chain is not null) evidence.Add(Probe.E(prefix + "chainStatus", string.Join(",", chain.ChainStatus.Select(s => s.Status.ToString())), Name));
                    // Inspection only: allow collection of an invalid certificate, never send application data.
                    return true;
                });
                await stream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = target.Name, EnabledSslProtocols = SslProtocols.None,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                    CertificateChainPolicy = new X509ChainPolicy { RevocationMode = X509RevocationMode.NoCheck, DisableCertificateDownloads = true }
                }, timeout.Token);
                evidence.Add(Probe.E($"tls.{port}.protocol", stream.SslProtocol.ToString(), Name));
                evidence.Add(Probe.E($"tls.{port}.cipher", stream.NegotiatedCipherSuite.ToString(), Name));
            }
            catch (Exception ex) when (ex is SocketException or AuthenticationException or IOException || ex is OperationCanceledException && !ct.IsCancellationRequested)
            { errors.Add($"{port}: {ex.Message}"); }
            await Task.Delay(options.DelayMs, ct);
        }
        return new(Name, target.Address, errors.Count > 0 ? ProbeStatus.Failed : ProbeStatus.Complete, evidence, [], errors.Count > 0 ? string.Join("; ", errors) : null);
    }
}
