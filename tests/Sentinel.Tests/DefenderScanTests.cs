using Sentinel.Engine.SystemInventory;

namespace Sentinel.Tests;

public sealed class DefenderScanTests
{
    [Fact]
    public void BuildArguments_Maps_Kinds()
    {
        Assert.Equal(
            "-Scan -ScanType 1",
            DefenderScan.BuildArguments(new DefenderScanRequest(DefenderScanKind.Quick, null)));
        Assert.Equal(
            "-Scan -ScanType 2",
            DefenderScan.BuildArguments(new DefenderScanRequest(DefenderScanKind.Full, null)));
    }

    [Fact]
    public void BuildArguments_Folder_Quotes_Resolved_Path()
    {
        string dir = Path.Combine(Path.GetTempPath(), "sentinel-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string args = DefenderScan.BuildArguments(
                new DefenderScanRequest(DefenderScanKind.Folder, dir));
            Assert.Equal($"-Scan -ScanType 3 -File \"{Path.GetFullPath(dir)}\"", args);
        }
        finally
        {
            Directory.Delete(dir);
        }
    }

    [Fact]
    public void ValidateFolder_Rejects_Missing()
    {
        Assert.Throws<ArgumentException>(() => DefenderScan.ValidateFolder(null));
        Assert.Throws<ArgumentException>(() => DefenderScan.ValidateFolder(
            Path.Combine(Path.GetTempPath(), "sentinel-nope-" + Guid.NewGuid().ToString("N"))));
    }

    [Fact]
    public void ResolveExe_BogusDir_IsNull()
    {
        Assert.Null(DefenderScan.ResolveExe(
            Path.Combine(Path.GetTempPath(), "sentinel-nope-" + Guid.NewGuid().ToString("N"))));
    }

    [Fact]
    public void Plan_Quick_Drafts_Command_Without_Launching()
    {
        // A03: the Threats buttons plan, never launch. Plan must
        // describe the exact MpCmdRun command and state plainly
        // that nothing started.
        var plan = DefenderScan.Plan(
            new DefenderScanRequest(DefenderScanKind.Quick, null));
        Assert.Contains("-Scan -ScanType 1", plan.CommandLine);
        Assert.Contains("nothing was started", plan.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Plan_Folder_Missing_Target_Explains()
    {
        var plan = DefenderScan.Plan(
            new DefenderScanRequest(
                DefenderScanKind.Folder,
                Path.Combine(Path.GetTempPath(), "sentinel-nope-" + Guid.NewGuid().ToString("N"))));
        Assert.False(plan.Ready);
        Assert.Contains("nothing was started", plan.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Plan_MissingTool_Explains()
    {
        var plan = DefenderScan.Plan(
            new DefenderScanRequest(DefenderScanKind.Full, null),
            exeOverrideDir: Path.Combine(
                Path.GetTempPath(), "sentinel-nope-" + Guid.NewGuid().ToString("N")));
        Assert.False(plan.Ready);
        Assert.Contains("nothing was started", plan.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Seam_MissingExe_NotStarted()
    {
        var launch = new ProcessDefenderProcess().Launch(
            Path.Combine(Path.GetTempPath(), "sentinel-nope-" + Guid.NewGuid().ToString("N") + ".exe"),
            "-Scan -ScanType 1", 1000, CancellationToken.None);
        Assert.False(launch.Started);
        Assert.Contains("Could not start", launch.Detail);
    }

    [Fact]
    public void Seam_Refusal_Maps_Exit_Code()
    {
        // whoami rejects MpCmdRun flags with a fast nonzero exit:
        // exercises process start + settle + exit mapping without
        // touching Defender itself. The accepted path (scan keeps
        // running) is proven live in the VM instead.
        string exe = Path.Combine(Environment.SystemDirectory, "whoami.exe");
        if (!File.Exists(exe))
        {
            return; // Non-Windows runner: nothing honest to assert.
        }

        var launch = new ProcessDefenderProcess().Launch(
            exe, "-Scan -ScanType 1", 10000, CancellationToken.None);
        Assert.True(launch.Started);
        Assert.True(launch.Exited);
        Assert.NotNull(launch.ExitCode);
        Assert.NotEqual(0, launch.ExitCode);
    }

    [Fact]
    public void Seam_Cancelled_StopsWaiting()
    {
        // ping -n 6 localhost runs ~5s: cancel mid-settle and the
        // seam reports started-but-waiting-stopped (it never kills).
        string exe = Path.Combine(Environment.SystemDirectory, "ping.exe");
        if (!File.Exists(exe))
        {
            return;
        }

        using var cts = new CancellationTokenSource();
        cts.CancelAfter(500);
        var launch = new ProcessDefenderProcess().Launch(
            exe, "-n 6 127.0.0.1", 30000, cts.Token);
        Assert.True(launch.Started);
        Assert.False(launch.Exited);
        Assert.Contains("cancelled", launch.Detail);
    }
}
