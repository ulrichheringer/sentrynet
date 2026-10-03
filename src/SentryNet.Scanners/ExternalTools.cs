using System.Diagnostics;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using SentryNet.Core;

namespace SentryNet.Scanners;

public sealed record ToolResult(int ExitCode, string Stdout, string Stderr);
public interface IProcessRunner
{
    Task<ToolResult> RunAsync(string executable, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct);
}
public sealed class ProcessRunner : IProcessRunner
{
    public async Task<ToolResult> RunAsync(string executable, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct)
    {
        using var process = new Process { StartInfo = new(executable)
        { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true } };
        foreach (var argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        if (!process.Start()) throw new IOException($"Could not start {executable}");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);
        async Task<string> ReadBoundedAsync(StreamReader reader)
        {
            var result = new StringBuilder(); var buffer = new char[4096];
            while (true)
            {
                var count = await reader.ReadAsync(buffer.AsMemory(), deadline.Token);
                if (count == 0) return result.ToString();
                if (result.Length + count > 4 * 1024 * 1024) { deadline.Cancel(); throw new IOException("External tool output exceeded 4 MiB."); }
                result.Append(buffer, 0, count);
            }
        }
        var stdout = ReadBoundedAsync(process.StandardOutput); var stderr = ReadBoundedAsync(process.StandardError);
        try
        {
            await Task.WhenAll(stdout, stderr, process.WaitForExitAsync(deadline.Token));
            return new(process.ExitCode, await stdout, await stderr);
        }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync(CancellationToken.None);
        }
    }
}
public sealed class NmapScanner(IProcessRunner runner) : IScanner
{
    public string Name => "nmap";
    public async Task<ProbeResult> ScanAsync(ResolvedTarget target, ScanOptions options, CancellationToken ct)
    {
        // No NSE scripts, OS detection, UDP sweep, shell, or user supplied command flags.
        var seconds = Math.Min(options.MaxDurationSeconds, Math.Max(10, (long)options.Ports.Length * (options.TimeoutMs + options.DelayMs) / 1000 + 10));
        var arguments = new List<string> { "-sT", "-sV", "--version-light", "-Pn", "-n", "--max-retries", "1", "--max-parallelism", "1",
            "--scan-delay", $"{Math.Max(10, options.DelayMs)}ms", "--host-timeout", $"{seconds}s", "-p", string.Join(",", options.Ports.Distinct()), "-oX", "-" };
        if (target.Address.Contains(':')) arguments.Add("-6");
        arguments.Add(target.Address);
        var result = await runner.RunAsync("nmap", arguments, TimeSpan.FromSeconds(seconds + 5), ct);
        if (result.ExitCode != 0) return new(Name, target.Address, ProbeStatus.Failed, [], [], $"Nmap exit {result.ExitCode}: {result.Stderr}");
        return Parse(result.Stdout, target.Address);
    }
    public static ProbeResult Parse(string xml, string expectedAddress)
    {
        using var reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings
        { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null, MaxCharactersInDocument = 4 * 1024 * 1024 });
        var document = XDocument.Load(reader);
        var host = document.Descendants("host").SingleOrDefault(h => h.Elements("address").Any(a => (string?)a.Attribute("addr") == expectedAddress));
        if (host is null) return new("nmap", expectedAddress, ProbeStatus.Failed, [], [], "Nmap returned no matching host (possibly timed out).");
        var services = new List<Service>(); var evidence = new List<Evidence>();
        foreach (var port in host.Descendants("port"))
        {
            var state = (string?)port.Element("state")?.Attribute("state") ?? "unknown";
            if (!int.TryParse((string?)port.Attribute("portid"), out var number) || number is < 1 or > 65535) continue;
            var protocol = (string?)port.Attribute("protocol") ?? "tcp";
            evidence.Add(Probe.E($"nmap.{protocol}.{number}", state, "nmap"));
            if (state != "open") continue;
            var service = port.Element("service");
            services.Add(new(number, protocol, (string?)service?.Attribute("name") ?? "unknown",
                (string?)service?.Attribute("product"), (string?)service?.Attribute("version")));
        }
        var finished = document.Root?.Element("runstats")?.Element("finished");
        var complete = (string?)finished?.Attribute("exit") == "success" && (string?)host.Element("status")?.Attribute("state") == "up" && host.Element("ports") is not null;
        return new("nmap", expectedAddress, complete ? ProbeStatus.Complete : ProbeStatus.Failed, evidence, services,
            complete ? null : "Nmap collection incomplete; absence of ports is inconclusive.");
    }
}
public sealed class DigScanner(IProcessRunner runner) : IScanner
{
    public string Name => "dig";
    public async Task<ProbeResult> ScanAsync(ResolvedTarget target, ScanOptions options, CancellationToken ct)
    {
        if (System.Net.IPAddress.TryParse(target.Name, out _)) return new(Name, target.Address, ProbeStatus.Skipped, [], [], "Domain record checks require an authorized hostname.");
        var evidence = new List<Evidence>(); var errors = new List<string>();
        foreach (var type in new[] { "A", "AAAA", "MX", "NS", "SOA", "TXT", "CAA", "DMARC" })
        {
            var name = type == "DMARC" ? "_dmarc." + target.Name : target.Name;
            var arguments = new List<string> { name, type == "DMARC" ? "TXT" : type,
                "+noall", "+answer", "+comments", "+tries=1", $"+time={Math.Max(1, options.TimeoutMs / 1000)}", "-p", options.DnsPort.ToString(System.Globalization.CultureInfo.InvariantCulture) };
            if (options.DnsServers.Length > 0) arguments.Add("@" + options.DnsServers[0]);
            var result = await runner.RunAsync("dig", arguments,
                TimeSpan.FromMilliseconds(options.TimeoutMs + 2000), ct);
            if (result.ExitCode != 0 || !(result.Stdout.Contains("status: NOERROR", StringComparison.Ordinal) || result.Stdout.Contains("status: NXDOMAIN", StringComparison.Ordinal)))
            { errors.Add($"{type}: DNS query unsuccessful (exit {result.ExitCode})."); continue; }
            var answers = ParseAnswers(result.Stdout);
            if (answers.Contains("\tCNAME\t", StringComparison.OrdinalIgnoreCase) &&
                !answers.Contains("\t" + (type == "DMARC" ? "TXT" : type) + "\t", StringComparison.OrdinalIgnoreCase))
            { errors.Add($"{type}: CNAME-only answer requires manual review."); continue; }
            evidence.Add(Probe.E("dns.record." + type.ToLowerInvariant(), answers, Name));
            evidence.Add(Probe.E("dns.query." + type.ToLowerInvariant(), name, Name));
            await Task.Delay(options.DelayMs, ct);
        }
        return new(Name, target.Address, errors.Count == 0 ? ProbeStatus.Complete : ProbeStatus.Failed, evidence, [], errors.Count == 0 ? null : string.Join("; ", errors));
    }
    public static string ParseAnswers(string text) => string.Join("\n", text.Split('\n').Select(s => s.Trim()).Where(s => s.Length > 0 && !s.StartsWith(';')));
}
