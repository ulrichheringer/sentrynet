using SentryNet.Core;

namespace SentryNet.Cli;

public sealed class Arguments
{
    private static readonly HashSet<string> Flags = ["authorized", "quiet", "json", "help"];
    private static readonly HashSet<string> Values = ["targets", "scope", "authorization-ref", "client", "engagement", "ports", "http-ports", "tls-ports", "dns-server", "dns-port", "scanners", "parallelism", "timeout-ms", "max-hosts", "delay-ms", "max-duration", "rules-file", "disable-rules", "severity", "config", "targets-file", "history-dir", "output", "formats", "baseline", "fail-on", "input", "current", "plugin", "profile"];
    private readonly Dictionary<string, string> options = new(StringComparer.Ordinal);
    public string Command { get; }
    public Arguments(string[] args)
    {
        Command = args.Length == 0 || args[0].StartsWith('-') ? "help" : args[0];
        for (var i = Command == "help" && (args.Length == 0 || args[0].StartsWith('-')) ? 0 : 1; i < args.Length; i++)
        {
            if (args[i] == "-h") { options["help"] = "true"; continue; }
            if (!args[i].StartsWith("--", StringComparison.Ordinal)) throw new ArgumentException($"Unexpected argument: {args[i]}");
            var name = args[i][2..];
            if (!Flags.Contains(name) && !Values.Contains(name)) throw new ArgumentException($"Unknown option: --{name}");
            if (options.ContainsKey(name)) throw new ArgumentException($"Duplicate option: --{name}");
            if (Flags.Contains(name)) { options[name] = "true"; continue; }
            if (++i >= args.Length || args[i].StartsWith("--", StringComparison.Ordinal)) throw new ArgumentException($"Missing value for --{name}");
            options[name] = args[i];
        }
    }
    public bool Has(string name) => options.ContainsKey(name);
    public string? Get(string name) => options.GetValueOrDefault(name);
    public string Get(string name, string fallback) => Get(name) ?? fallback;
    public string Require(string name) => Get(name) ?? throw new ArgumentException($"--{name} is required.");
    public static string[] Csv(string value) => value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
    private int Number(string name, int fallback) => Has(name) ? int.TryParse(Get(name), out var n) ? n : throw new ArgumentException($"--{name} must be an integer.") : fallback;
    public static int[] ParsePorts(string value)
    {
        var ports = new HashSet<int>();
        foreach (var segment in Csv(value))
        {
            var range = segment.Split('-');
            if (range.Length > 2 || !int.TryParse(range[0], out var first) || first is < 1 or > 65535) throw new ArgumentException("Invalid port specification.");
            var last = first;
            if (range.Length == 2 && (!int.TryParse(range[1], out last) || last < first || last > 65535)) throw new ArgumentException("Invalid port range.");
            if (last - first > 4095) throw new ArgumentException("A port range cannot exceed 4096 ports.");
            for (var port = first; port <= last; port++) ports.Add(port);
            if (ports.Count > 4096) throw new ArgumentException("Port count exceeds 4096.");
        }
        if (ports.Count == 0) throw new ArgumentException("No ports selected.");
        return ports.Order().ToArray();
    }
    public ScanOptions Apply(ScanOptions original)
    {
        var profile = Get("profile");
        if (profile is not (null or "quick" or "standard" or "full")) throw new ArgumentException("Profiles: quick, standard, full.");
        var defaults = profile switch
        {
            "quick" => original with { Scanners = ["dns", "tcp"], Ports = [22, 80, 443, 445, 3389] },
            "full" => original with { Scanners = ["dns", "ping", "tcp", "http", "tls", "dig", "nmap"] },
            "standard" => original with { Scanners = ["dns", "tcp", "http", "tls"] }, _ => original
        };
        var overrides = new Dictionary<string, Severity>(defaults.SeverityOverrides, StringComparer.OrdinalIgnoreCase);
        foreach (var item in Csv(Get("severity", "")))
        {
            var parts = item.Split('=');
            if (parts.Length != 2 || !Enum.TryParse<Severity>(parts[1], true, out var s) || !Enum.IsDefined(s)) throw new ArgumentException("Use --severity RULE_ID=High,RULE_ID=Low.");
            overrides[parts[0]] = s;
        }
        return defaults with
        {
            Targets = Has("targets") ? Csv(Require("targets")) : defaults.Targets,
            Scope = Has("scope") ? Csv(Require("scope")) : defaults.Scope,
            // Authorization must be consciously acknowledged for each CLI execution, even with a config file.
            Authorized = Has("authorized"), AuthorizationReference = Get("authorization-ref", defaults.AuthorizationReference),
            Client = Get("client", defaults.Client), Engagement = Get("engagement", defaults.Engagement),
            Ports = Has("ports") ? ParsePorts(Require("ports")) : defaults.Ports,
            HttpPorts = Has("http-ports") ? ParsePorts(Require("http-ports")) : defaults.HttpPorts,
            TlsPorts = Has("tls-ports") ? ParsePorts(Require("tls-ports")) : defaults.TlsPorts,
            DnsServers = Has("dns-server") ? Csv(Require("dns-server")) : defaults.DnsServers, DnsPort = Number("dns-port", defaults.DnsPort),
            Scanners = Has("scanners") ? Csv(Require("scanners")) : defaults.Scanners,
            Parallelism = Number("parallelism", defaults.Parallelism), TimeoutMs = Number("timeout-ms", defaults.TimeoutMs),
            MaxHosts = Number("max-hosts", defaults.MaxHosts), DelayMs = Number("delay-ms", defaults.DelayMs), MaxDurationSeconds = Number("max-duration", defaults.MaxDurationSeconds),
            RulesFile = Get("rules-file", defaults.RulesFile ?? "") is { Length: > 0 } file ? file : null,
            DisabledRules = Has("disable-rules") ? Csv(Require("disable-rules")) : defaults.DisabledRules,
            SeverityOverrides = overrides
        };
    }
}
