using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using SentryNet.Core;

namespace SentryNet.Scanners;

internal static class Probe
{
    public static Evidence E(string key, string value, string source) => new(key, value, source, DateTimeOffset.UtcNow);
    public static string Endpoint(string address, int port) => IPAddress.Parse(address).AddressFamily == AddressFamily.InterNetworkV6 ? $"[{address}]:{port}" : $"{address}:{port}";
    public static CancellationTokenSource Timeout(ScanOptions options, CancellationToken ct)
    {
        var source = CancellationTokenSource.CreateLinkedTokenSource(ct);
        source.CancelAfter(options.TimeoutMs);
        return source;
    }
}
public sealed class TcpScanner : IScanner
{
    public string Name => "tcp";
    public async Task<ProbeResult> ScanAsync(ResolvedTarget target, ScanOptions options, CancellationToken ct)
    {
        var services = new List<Service>(); var evidence = new List<Evidence>();
        var uncertain = 0;
        foreach (var port in options.Ports.Distinct().Order())
        {
            ct.ThrowIfCancellationRequested();
            using var timeout = Probe.Timeout(options, ct);
            using var client = new TcpClient(IPAddress.Parse(target.Address).AddressFamily);
            try
            {
                await client.ConnectAsync(IPAddress.Parse(target.Address), port, timeout.Token);
                services.Add(new(port, "tcp", ServiceName(port)));
                evidence.Add(Probe.E($"tcp.{port}", "open", Name));
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
            { evidence.Add(Probe.E($"tcp.{port}", "closed", Name)); }
            catch (Exception ex) when (ex is SocketException || ex is OperationCanceledException && !ct.IsCancellationRequested)
            { uncertain++; evidence.Add(Probe.E($"tcp.{port}", "unreachable-or-filtered", Name)); }
            await Task.Delay(options.DelayMs, ct);
        }
        return new(Name, target.Address, uncertain > 0 ? ProbeStatus.Failed : ProbeStatus.Complete, evidence, services,
            uncertain > 0 ? $"{uncertain} ports could not be classified; timeouts do not prove closed ports." : null);
    }
    public static string ServiceName(int port) => port switch
    {
        21 => "ftp", 22 => "ssh", 23 => "telnet", 25 => "smtp", 53 => "dns", 80 or 8080 or 8000 => "http",
        110 => "pop3", 139 => "netbios", 143 => "imap", 443 or 8443 => "https", 445 => "smb", 1433 => "mssql",
        3306 => "mysql", 3389 => "rdp", 5432 => "postgresql", 6379 => "redis", 27017 => "mongodb", _ => "unknown"
    };
}
public sealed class PingScanner : IScanner
{
    public string Name => "ping";
    public async Task<ProbeResult> ScanAsync(ResolvedTarget target, ScanOptions options, CancellationToken ct)
    {
        using var ping = new Ping();
        var reply = await ping.SendPingAsync(IPAddress.Parse(target.Address), TimeSpan.FromMilliseconds(options.TimeoutMs), cancellationToken: ct);
        return new(Name, target.Address, reply.Status == IPStatus.Success ? ProbeStatus.Complete : ProbeStatus.Failed,
            [Probe.E("icmp.status", reply.Status.ToString(), Name), Probe.E("icmp.rttMs", reply.RoundtripTime.ToString(), Name)], [],
            reply.Status == IPStatus.Success ? null : "ICMP may be blocked; this does not prove the host is offline.");
    }
}
public static class LocalInventory
{
    public static object Collect() => NetworkInterface.GetAllNetworkInterfaces().Select(n => new
    {
        n.Name, Description = n.Description, Status = n.OperationalStatus.ToString(), Type = n.NetworkInterfaceType.ToString(),
        Mac = n.GetPhysicalAddress().ToString(), Addresses = n.GetIPProperties().UnicastAddresses.Select(a => new { Address = a.Address.ToString(), a.PrefixLength }),
        Gateways = n.GetIPProperties().GatewayAddresses.Select(g => g.Address.ToString()),
        DnsServers = n.GetIPProperties().DnsAddresses.Select(a => a.ToString())
    }).ToArray();
}
