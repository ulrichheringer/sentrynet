using System.Reflection;
using System.Runtime.Loader;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using SentryNet.Core;
using SentryNet.Scanners;

namespace SentryNet.Cli;

public static class CliApplication
{
    public static async Task<int> RunAsync(string[] argv)
    {
        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; cancellation.Cancel(); };
        Console.CancelKeyPress += cancel;
        try
        {
            var args = new Arguments(argv); var ct = cancellation.Token;
            if (args.Has("help") || args.Command == "help") { Console.WriteLine(Help); return 0; }
            var store = new FileReportStore(args.Get("history-dir", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentryNet", "history")));
            switch (args.Command)
            {
                case "version": Console.WriteLine("SentryNet 0.1.0 / .NET 8 / schema 1.0"); return 0;
                case "inventory": WriteJson(LocalInventory.Collect()); return 0;
                case "rules": WriteJson(BuiltinRules.Catalog); return 0;
                case "doctor": return await DoctorAsync(ct);
                case "init":
                    var configPath = args.Get("output", "sentrynet.json");
                    if (File.Exists(configPath)) throw new ArgumentException("Config already exists; choose another --output.");
                    await AtomicFile.WriteAsync(configPath, JsonSerializer.Serialize(new ScanOptions { Targets = ["127.0.0.1"], Scope = ["127.0.0.1"], AuthorizationReference = "Replace with written authorization reference" }, JsonDefaults.Options), ct);
                    Console.WriteLine(configPath); return 0;
                case "history":
                    var history = await store.ListAsync(args.Get("client", "default"), ct);
                    WriteJson(history.Select(r => new { r.Id, r.StartedAt, r.Options.Client, r.Options.Engagement, r.Complete, Targets = r.Targets.Count, Findings = r.Findings.Count, Path = store.ReportPath(r) })); return 0;
                case "diff":
                    var old = await store.LoadAsync(args.Require("baseline"), ct);
                    var current = await store.LoadAsync(args.Require("current"), ct);
                    var difference = BaselineComparer.Compare(old, current);
                    if (args.Has("output")) await AtomicFile.WriteAsync(args.Require("output"), JsonSerializer.Serialize(difference, JsonDefaults.Options), ct);
                    WriteJson(difference); return 0;
                case "report":
                    var report = await store.LoadAsync(args.Require("input"), ct);
                    ScanDiff? diff = args.Has("baseline") ? BaselineComparer.Compare(await store.LoadAsync(args.Require("baseline"), ct), report) : null;
                    await ExportAsync(report, args.Get("output", "report"), Formats(args), diff, ct); return 0;
                case "demo":
                    var demo = DemoReport.Create();
                    await ExportAsync(demo, args.Get("output", Path.Combine("reports", "demo")), Formats(args), null, ct);
                    if (args.Has("json")) WriteJson(demo); else Console.WriteLine("Synthetic offline report generated; no network requests were made."); return 0;
                case "scan": case "discover": case "plan": break;
                default: throw new ArgumentException($"Unknown command: {args.Command}");
            }
            // Validate output format and threshold before any network request.
            var formats = Formats(args); Severity? threshold = null;
            if (args.Has("fail-on"))
            {
                if (!Enum.TryParse<Severity>(args.Require("fail-on"), true, out var parsed) || !Enum.IsDefined(parsed)) throw new ArgumentException("Invalid severity threshold.");
                threshold = parsed;
            }
            var options = new ScanOptions();
            if (args.Has("config"))
            {
                if (new FileInfo(args.Require("config")).Length > 1024 * 1024) throw new ArgumentException("Config exceeds 1 MiB.");
                using var file = File.OpenRead(args.Require("config"));
                options = await JsonSerializer.DeserializeAsync<ScanOptions>(file, JsonDefaults.Options, ct) ?? throw new ArgumentException("Invalid config.");
            }
            options = args.Apply(options);
            if (args.Has("targets-file"))
            {
                var path = args.Require("targets-file");
                if (new FileInfo(path).Length > 1024 * 1024) throw new ArgumentException("Targets file exceeds 1 MiB.");
                var targets = (await File.ReadAllLinesAsync(path, ct)).Select(s => s.Trim()).Where(s => s.Length > 0 && !s.StartsWith('#')).ToArray();
                options = options with { Targets = options.Targets.Concat(targets).Distinct().ToArray() };
            }
            if (args.Command == "discover" && !args.Has("scanners")) options = options with { Scanners = ["ping", "tcp"] };
            options.Validate(requireAuthorization: args.Command != "plan");
            // Read baseline before scanning so a bad path fails without active work.
            var baseline = args.Has("baseline") ? await store.LoadAsync(args.Require("baseline"), ct) : null;
            var services = new ServiceCollection();
            services.AddSingleton<IProcessRunner, ProcessRunner>();
            services.AddSingleton<IScanner, DnsScanner>(); services.AddSingleton<IScanner, PingScanner>();
            services.AddSingleton<IScanner, TcpScanner>(); services.AddSingleton<IScanner, HttpScanner>();
            services.AddSingleton<IScanner, TlsScanner>(); services.AddSingleton<IScanner, NmapScanner>(); services.AddSingleton<IScanner, DigScanner>();
            services.AddSingleton<IRule, BuiltinRules>();
            if (options.RulesFile is not null) services.AddSingleton<IRule>(await JsonRuleSet.LoadAsync(options.RulesFile, ct));
            foreach (var path in Arguments.Csv(args.Get("plugin", ""))) RegisterPlugin(services, path);
            services.AddSingleton<ScanEngine>();
            using var provider = services.BuildServiceProvider();
            var engine = provider.GetRequiredService<ScanEngine>();
            if (options.Scanners.Any(n => !engine.ScannerNames.Contains(n, StringComparer.OrdinalIgnoreCase))) throw new ArgumentException("Unknown scanner; use dns,ping,tcp,http,tls,nmap,dig or an explicitly loaded plugin.");
            if (args.Command == "plan")
            {
                var policy = new ScopePolicy(options.Scope);
                var targets = options.Targets.SelectMany(t => t.Contains('/') ? ScopePolicy.ExpandCidr(t, options.MaxHosts) : new[] { ScopePolicy.Normalize(t) }).Distinct().ToArray();
                if (targets.Length > options.MaxHosts) throw new ArgumentException("Target count exceeds host limit.");
                foreach (var target in targets)
                {
                    ScopePolicy.ValidateEntry(target);
                    if (System.Net.IPAddress.TryParse(target, out var ip) ? !policy.AllowsAddress(ip) : !policy.AllowsName(target)) throw new ArgumentException($"Target outside scope: {target}");
                }
                WriteJson(new { Mode = "offline-plan", TargetCount = targets.Length, Targets = targets, Options = options, Note = "No DNS or target probes. Actual addresses and global host limit are verified at execution." }); return 0;
            }
            var progress = args.Has("quiet") || args.Has("json") ? null : new Progress<string>(message => Console.Error.WriteLine(message));
            var result = await engine.ScanAsync(options, progress, ct);
            await store.SaveAsync(result, ct);
            var prefix = args.Get("output", Path.Combine("reports", result.Id.ToString()));
            var delta = baseline is null ? null : BaselineComparer.Compare(baseline, result);
            await ExportAsync(result, prefix, formats, delta, ct);
            if (delta is not null) await AtomicFile.WriteAsync(prefix + ".diff.json", JsonSerializer.Serialize(delta, JsonDefaults.Options), ct);
            if (args.Has("json")) WriteJson(result);
            else Console.WriteLine($"Scan {result.Id}: {result.Targets.Count} targets, {result.Findings.Count} findings, {result.Probes.Count(p => p.Status != ProbeStatus.Complete)} incomplete probes.\nReports: {Path.GetFullPath(prefix)}.*\nHistory: {store.ReportPath(result)}");
            if (!result.Complete) return 3;
            return threshold.HasValue && result.Findings.Any(f => f.Severity >= threshold.Value) ? 2 : 0;
        }
        catch (OperationCanceledException) { Console.Error.WriteLine("Scan cancelled or deadline exceeded; incomplete scan was not saved as a completed report."); return 130; }
        catch (Exception ex) when (ex is ArgumentException or IOException or JsonException or InvalidOperationException or System.Net.Sockets.SocketException or System.ComponentModel.Win32Exception or ReflectionTypeLoadException or UnauthorizedAccessException)
        { Console.Error.WriteLine($"Error: {ex.Message}"); return 1; }
        finally { Console.CancelKeyPress -= cancel; }
    }
    private static string[] Formats(Arguments args)
    {
        var formats = Arguments.Csv(args.Get("formats", "json,html")).Distinct().ToArray();
        if (formats.Length == 0 || formats.Any(f => f is not ("json" or "html" or "sarif"))) throw new ArgumentException("Formats: json,html,sarif.");
        return formats;
    }
    private static async Task ExportAsync(ScanReport r, string prefix, string[] formats, ScanDiff? diff, CancellationToken ct)
    {
        foreach (var format in formats)
        {
            var path = prefix + "." + format;
            switch (format)
            {
                case "json": await ReportExporter.JsonAsync(r, path, ct); break;
                case "html": await ReportExporter.HtmlAsync(r, path, diff, ct); break;
                case "sarif": await ReportExporter.SarifAsync(r, path, ct); break;
            }
        }
    }
    private static void RegisterPlugin(IServiceCollection services, string path)
    {
        var assembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.GetFullPath(path));
        var types = assembly.GetTypes().Where(t => t.IsClass && !t.IsAbstract && typeof(ISentryNetPlugin).IsAssignableFrom(t)).ToArray();
        if (types.Length == 0) throw new ArgumentException($"No ISentryNetPlugin found: {path}");
        foreach (var type in types)
        {
            var plugin = (ISentryNetPlugin)(Activator.CreateInstance(type) ?? throw new ArgumentException($"Cannot instantiate {type.Name}"));
            foreach (var scanner in plugin.CreateScanners()) services.AddSingleton(scanner);
            foreach (var rule in plugin.CreateRules()) services.AddSingleton(rule);
            Console.Error.WriteLine($"Loaded trusted plugin: {plugin.Name} {plugin.Version}");
        }
    }
    private static async Task<int> DoctorAsync(CancellationToken ct)
    {
        var runner = new ProcessRunner(); var tools = new List<object>();
        foreach (var (name, args) in new[] { ("nmap", new[] { "--version" }), ("dig", new[] { "-v" }) })
        {
            try
            {
                var result = await runner.RunAsync(name, args, TimeSpan.FromSeconds(5), ct);
                tools.Add(new { Name = name, Available = result.ExitCode == 0, Version = result.Stdout.Split('\n').FirstOrDefault() });
            }
            catch (Exception ex) when (ex is IOException or System.ComponentModel.Win32Exception || ex is OperationCanceledException && !ct.IsCancellationRequested)
            { tools.Add(new { Name = name, Available = false, Error = ex.Message }); }
        }
        WriteJson(new { Runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription, OS = System.Runtime.InteropServices.RuntimeInformation.OSDescription, Tools = tools }); return 0;
    }
    private static void WriteJson(object value) => Console.WriteLine(JsonSerializer.Serialize(value, JsonDefaults.Options));
    private const string Help = """
        SentryNet 0.1 — authorized defensive network auditing (.NET 8)

        Commands:
          scan       Collect inventory, evidence and findings; save history and reports
          discover   Scan using ICMP and TCP (same explicit authorization requirements)
          plan       Validate scope and show an OFFLINE execution plan; no DNS or probes
          inventory  List local interfaces, addresses, gateways and DNS servers; no probes
          rules      List built-in rule IDs, severities, recommendations and references
          init       Write a sample config (--output sentrynet.json)
          doctor     Check runtime and optional nmap/dig installation (no network probes)
          history    List stored scans (--client NAME, --history-dir PATH)
          diff       Compare --baseline FILE --current FILE [--output diff.json]
          report     Export --input FILE [--baseline FILE] --output PREFIX
          demo       Generate synthetic offline reports for review
          version    Print version

        Active scan requires:
          --targets HOST,IP,CIDR --scope HOST,IP,CIDR
          --authorized --authorization-ref "Written authorization / engagement ID"

        Options:
          --config FILE              JSON defaults (authorization still requires CLI flag)
          --targets-file FILE        One target per line; # comments supported
          --client NAME --engagement NAME
          --profile quick|standard|full   Full enables optional Nmap and dig
          --ports 22,80,443,8000-8010 --scanners dns,ping,tcp,http,tls,nmap,dig
          --http-ports 80,443,8080 --tls-ports 443,8443 (mappings intersect --ports)
          --parallelism 8 --timeout-ms 3000 --max-hosts 256 --delay-ms 50
          --max-duration 600          Global deadline in seconds
          --rules-file FILE --disable-rules HTTP003,NET003 --severity NET003=Low
          --plugin DLL[,DLL]         Explicitly load TRUSTED code with ISentryNetPlugin
          --output PREFIX --formats json,html,sarif --baseline FILE
          --history-dir PATH --fail-on Medium --quiet --json

        Exit codes: 0 success, 1 input/operational error, 2 severity threshold met,
        3 incomplete collection (takes precedence over threshold), 130 cancelled/deadline.
        Use only on your own or explicitly authorized systems. No exploitation.
        """;
}
