using SentryNet.Scanners;

namespace SentryNet.Tests;

public sealed class ProcessRunnerTests
{
    private static string CliDll => typeof(SentryNet.Cli.CliApplication).Assembly.Location;
    [Fact]
    public async Task CliRejectsUnauthorizedScanWithExitCodeOne()
    {
        var result = await new ProcessRunner().RunAsync("dotnet", [CliDll, "scan", "--targets", "127.0.0.1", "--scope", "127.0.0.1"], TimeSpan.FromSeconds(15), default);
        Assert.Equal(1, result.ExitCode); Assert.Contains("authorization", result.Stderr, StringComparison.OrdinalIgnoreCase);
    }
    [Fact]
    public async Task OfflinePlanUsesMachineReadableOutput()
    {
        var result = await new ProcessRunner().RunAsync("dotnet", [CliDll, "plan", "--targets", "192.0.2.0/30", "--scope", "192.0.2.0/24", "--profile", "quick"], TimeSpan.FromSeconds(15), default);
        Assert.Equal(0, result.ExitCode);
        using var json = System.Text.Json.JsonDocument.Parse(result.Stdout);
        Assert.Equal(2, json.RootElement.GetProperty("targetCount").GetInt32());
    }
    [Fact]
    public async Task ActualCliWritesReportAndHistoryForOwnedLoopback()
    {
        var root = Path.Combine(Path.GetTempPath(), "sentrynet-e2e-" + Guid.NewGuid());
        using var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0); listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        try
        {
            var result = await new ProcessRunner().RunAsync("dotnet", [CliDll, "scan", "--targets", "127.0.0.1", "--scope", "127.0.0.1", "--authorized", "--authorization-ref", "Owned loopback fixture", "--scanners", "tcp", "--ports", port.ToString(), "--output", Path.Combine(root, "report"), "--history-dir", Path.Combine(root, "history"), "--json"], TimeSpan.FromSeconds(15), default);
            Assert.Equal(0, result.ExitCode);
            using var json = System.Text.Json.JsonDocument.Parse(result.Stdout);
            Assert.True(json.RootElement.GetProperty("complete").GetBoolean());
            Assert.True(File.Exists(Path.Combine(root, "report.html"))); Assert.True(File.Exists(Path.Combine(root, "report.json")));
            Assert.Single(Directory.EnumerateFiles(Path.Combine(root, "history"), "*.json", SearchOption.AllDirectories));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }
}
