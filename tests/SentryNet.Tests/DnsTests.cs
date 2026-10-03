using System.Net;
using System.Net.Sockets;
using System.Text;
using DnsClient;
using SentryNet.Core;
using SentryNet.Scanners;

namespace SentryNet.Tests;

public sealed class DnsTests
{
    [Fact]
    public async Task NativeResolverParsesOwnedUdpDnsFixtureAndJoinsTxtChunks()
    {
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var server = Task.Run(async () =>
        {
            var request = await udp.ReceiveAsync(deadline.Token);
            var questionEnd = 12;
            while (request.Buffer[questionEnd] != 0) questionEnd += request.Buffer[questionEnd] + 1;
            var response = request.Buffer.Take(questionEnd + 5).ToList();
            response[2] = 0x81; response[3] = 0x80; response[6] = 0; response[7] = 1;
            response[10] = 0; response[11] = 0;
            var first = Encoding.ASCII.GetBytes("v=spf1 "); var second = Encoding.ASCII.GetBytes("-all");
            response.AddRange(new byte[] { 0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60, 0, (byte)(first.Length + second.Length + 2), (byte)first.Length });
            response.AddRange(first); response.Add((byte)second.Length); response.AddRange(second);
            await udp.SendAsync(response.ToArray(), request.RemoteEndPoint, deadline.Token);
        }, deadline.Token);
        var result = await new DnsRecordResolver().QueryAsync("example.test", QueryType.TXT,
            TestData.Options() with { DnsServers = ["127.0.0.1"], DnsPort = port }, deadline.Token);
        await server;
        Assert.True(result.Success, result.Error); Assert.Contains("v=spf1 -all", result.Records); Assert.Contains("127.0.0.1", result.Resolver);
    }
    [Fact]
    public async Task FailedRecordQueryDoesNotProduceAbsenceEvidence()
    {
        var result = await new DnsScanner(new FixtureResolver()).ScanAsync(new("example.test", "127.0.0.1"), TestData.Options(), default);
        Assert.Equal(ProbeStatus.Failed, result.Status);
        Assert.DoesNotContain(result.Evidence, e => e.Key == "dns.record.dmarc");
        Assert.Contains(result.Evidence, e => e.Key == "dns.record.mx");
        Assert.DoesNotContain(new BuiltinRules().Evaluate([result]), f => f.RuleId == "DNS004");
    }
    [Fact]
    public async Task LiteralInventoryRequiresNoExtraDnsQueries()
    {
        var resolver = new FixtureResolver();
        var result = await new DnsScanner(resolver).ScanAsync(new("127.0.0.1", "127.0.0.1"), TestData.Options(), default);
        Assert.Equal(0, resolver.Calls); Assert.Equal(ProbeStatus.Complete, result.Status);
    }
    private sealed class FixtureResolver : IDnsRecordResolver
    {
        public int Calls;
        public Task<DnsRecordResponse> QueryAsync(string name, QueryType type, ScanOptions options, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult(name.StartsWith("_dmarc.", StringComparison.Ordinal)
                ? new DnsRecordResponse(false, "", "127.0.0.1", "ServerFailure", "SERVFAIL")
                : new DnsRecordResponse(true, type == QueryType.MX ? "example.test. 60 IN MX 10 mail.example.test." : "", "127.0.0.1", "NoError"));
        }
    }
}
