using System.Net;
using System.Net.NetworkInformation;
using DnsClient;
using DnsClient.Protocol;
using SentryNet.Core;

namespace SentryNet.Scanners;

public sealed record DnsRecordResponse(bool Success, string Records, string Resolver, string Status, string? Error = null);
public interface IDnsRecordResolver
{
    Task<DnsRecordResponse> QueryAsync(string name, QueryType type, ScanOptions options, CancellationToken ct);
}
public sealed class DnsRecordResolver : IDnsRecordResolver
{
    public async Task<DnsRecordResponse> QueryAsync(string name, QueryType type, ScanOptions options, CancellationToken ct)
    {
        // Never silently fall back to third-party public resolvers.
        var addresses = options.DnsServers.Length > 0 ? options.DnsServers.Select(IPAddress.Parse).ToArray() :
            NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up)
                .SelectMany(n => n.GetIPProperties().DnsAddresses).Distinct().Take(8).ToArray();
        if (addresses.Length == 0) return new(false, "", "", "unavailable", "No system DNS resolver is configured; supply --dns-server.");
        var servers = addresses.Select(a => new NameServer(new IPEndPoint(a, options.DnsPort))).ToArray();
        var client = new LookupClient(new LookupClientOptions(servers)
        {
            AutoResolveNameServers = false,
            UseCache = false,
            Retries = 0,
            Timeout = TimeSpan.FromMilliseconds(options.TimeoutMs),
            ThrowDnsErrors = false,
            ContinueOnDnsError = false,
            UseRandomNameServer = false
        });
        using var deadline = Probe.Timeout(options, ct);
        try
        {
            var result = await client.QueryAsync(name.TrimEnd('.') + ".", type, QueryClass.IN, deadline.Token);
            var valid = (DnsResponseCode)result.Header.ResponseCode is DnsResponseCode.NoError or DnsResponseCode.NotExistentDomain;
            var selected = result.Answers.Where(r => (int)r.RecordType == (int)type).ToArray();
            // A CNAME-only answer is not proof that the requested control is missing. Do not chase new targets.
            if (valid && selected.Length == 0 && result.Answers.CnameRecords().Any())
                return new(false, "", result.NameServer.ToString(), "cname-only", "Requested record absent from a CNAME-only answer; inherited policy requires manual review.");
            var records = string.Join("\n", selected.Select(r => r is TxtRecord txt
                ? $"{r.DomainName} {r.TimeToLive} IN TXT \"{string.Concat(txt.Text)}\"" : r.ToString()));
            return new(valid, records, result.NameServer.ToString(), result.Header.ResponseCode.ToString(), valid ? null : result.ErrorMessage);
        }
        catch (Exception ex) when (ex is DnsResponseException || ex is OperationCanceledException && !ct.IsCancellationRequested)
        { return new(false, "", string.Join(",", addresses.Select(a => a.ToString())), "failed", ex.Message); }
    }
}
public sealed class DnsScanner(IDnsRecordResolver resolver) : IScanner
{
    public string Name => "dns";
    public async Task<ProbeResult> ScanAsync(ResolvedTarget target, ScanOptions options, CancellationToken ct)
    {
        var evidence = new List<Evidence> { Probe.E("dns.name", target.Name, Name), Probe.E("dns.address", target.Address, Name) };
        // IP connections always use the engine's pinned address. Record queries are advisory, never connection targets.
        if (IPAddress.TryParse(target.Name, out _)) return new(Name, target.Address, ProbeStatus.Complete, evidence, []);
        var errors = new List<string>();
        foreach (var (label, type) in new[] { ("a", QueryType.A), ("aaaa", QueryType.AAAA), ("mx", QueryType.MX),
            ("ns", QueryType.NS), ("soa", QueryType.SOA), ("txt", QueryType.TXT), ("caa", QueryType.CAA), ("dmarc", QueryType.TXT) })
        {
            var name = label == "dmarc" ? "_dmarc." + target.Name : target.Name;
            var result = await resolver.QueryAsync(name, type, options, ct);
            evidence.Add(Probe.E("dns.status." + label, result.Status, Name));
            evidence.Add(Probe.E("dns.resolver." + label, result.Resolver, Name));
            if (result.Success)
            {
                evidence.Add(Probe.E("dns.record." + label, result.Records, Name));
                evidence.Add(Probe.E("dns.query." + label, name, Name));
            }
            else errors.Add($"{label}: {result.Error}");
            await Task.Delay(options.DelayMs, ct);
        }
        return new(Name, target.Address, errors.Count == 0 ? ProbeStatus.Complete : ProbeStatus.Failed, evidence, [], errors.Count == 0 ? null : string.Join("; ", errors));
    }
}
