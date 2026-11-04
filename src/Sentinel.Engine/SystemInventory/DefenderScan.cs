using System.Diagnostics;

namespace Sentinel.Engine.SystemInventory;

public enum DefenderScanKind
{
    Quick,
    Full,
    Folder,
    // Offline (Windows Defender Offline): reboots into the offline
    // environment and scans outside Windows. Restart acknowledgement
    // + platform support required; T50-gated like everything else.
    Offline,
}

// A request to Microsoft Defender (the protection engine stays
// authoritative; Sentinel only asks it to scan). Folder scans
// need an existing file or directory; nothing is uploaded.
public sealed record DefenderScanRequest(DefenderScanKind Kind, string? Path);

public sealed record DefenderLaunch(
    bool Started,
    int? ProcessId,
    bool Exited,
    int? ExitCode,
    string Detail);

// A03 containment (T50 update): a drafted request the UI may show
// but must not execute. Ready means the target validates AND the
// tool exists; it never means "launched". Only the defender_scan
// executor (through IDefenderProcess) may turn a plan into a
// launch. Direct Process.Start callers are forbidden.
public sealed record DefenderScanPlan(
    string KindLabel,
    string CommandLine,
    bool Ready,
    string Detail);

// T50: the process seam behind defender_scan. Production launches
// MpCmdRun (or the fixed offline command) and settles briefly;
// tests inject scripted launches. The seam NEVER kills: once
// Defender owns a scan, cancellation stops Sentinel waiting —
// never the scan itself.
public interface IDefenderProcess
{
    DefenderLaunch Launch(string exe, string args, int settleMs, CancellationToken ct);
}

public sealed class ProcessDefenderProcess : IDefenderProcess
{
    public DefenderLaunch Launch(string exe, string args, int settleMs, CancellationToken ct)
    {
        Process? proc;
        try
        {
            proc = Process.Start(new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
        }
        catch (Exception ex)
        {
            return new DefenderLaunch(false, null, true, null,
                $"Could not start Defender ({ex.GetType().Name}: {Trim(ex.Message)}).");
        }

        if (proc is null)
        {
            return new DefenderLaunch(false, null, true, null,
                "Defender did not start (no process).");
        }

        using (proc)
        {
            // Sliced settle: a real scan outlives it (running
            // state); immediate refusal exits fast with a code.
            int waited = 0;
            while (waited < settleMs)
            {
                if (ct.IsCancellationRequested)
                {
                    return new DefenderLaunch(true, proc.Id, false, null,
                        "Sentinel stopped waiting (cancelled) — the Defender scan continues; " +
                        "progress shows in Windows Security.");
                }

                if (proc.WaitForExit(250))
                {
                    return new DefenderLaunch(true, proc.Id, true, proc.ExitCode,
                        $"Defender exited during launch settle (exit {proc.ExitCode}).");
                }

                waited += 250;
            }

            return new DefenderLaunch(true, proc.Id, false, null,
                "Defender scan launched and still running after the settle window.");
        }
    }

    private static string Trim(string s)
    {
        s = (s ?? string.Empty).Trim().ReplaceLineEndings(" ");
        return s.Length <= 200 ? s : s[..200];
    }
}

// MpCmdRun draft + launcher (02 §9, T50). Launching Defender
// is NOT read-only: a scan runs for minutes to hours and
// Defender may remediate under its own policy. So the UI may
// only Plan (draft) + Confirm (sheet); the executor launches
// through IDefenderProcess, settles briefly to catch immediate
// refusal (missing tool, access denied), then hands progress
// back to Windows Security.
public static class DefenderScan
{
    public static string BuildArguments(DefenderScanRequest request)
    {
        return request.Kind switch
        {
            DefenderScanKind.Quick => "-Scan -ScanType 1",
            DefenderScanKind.Full => "-Scan -ScanType 2",
            DefenderScanKind.Folder => "-Scan -ScanType 3 -File \"" +
                ValidateFolder(request.Path) + "\"",
            // Offline has no MpCmdRun form — see OfflineCommand.
            _ => throw new ArgumentOutOfRangeException(nameof(request)),
        };
    }

    // The offline trigger: a FIXED command, never interpolated.
    // Start-MpWDOScan exists on Windows 10/11 clients; anything
    // else (Server, unknown) refuses via OfflineSupported.
    public static (string Exe, string Args) OfflineCommand() =>
        ("powershell.exe", "-NoProfile -NonInteractive -Command Start-MpWDOScan");

    public static bool OfflineSupported(Func<int?>? productTypeReader = null)
    {
        if (Environment.OSVersion.Platform != PlatformID.Win32NT)
        {
            return false;
        }

        int? productType;
        try
        {
            // A provided reader answering unknown stays unknown —
            // it must NOT fall through to the live WMI read.
            productType = productTypeReader is not null
                ? productTypeReader()
                : ReadProductType();
        }
        catch
        {
            return false;
        }

        // Win32_OperatingSystem ProductType: 1 = workstation.
        return productType == 1;
    }

    private static int? ReadProductType()
    {
        using var searcher = new System.Management.ManagementObjectSearcher(
            "SELECT ProductType FROM Win32_OperatingSystem");
        foreach (System.Management.ManagementObject os in searcher.Get())
        {
            using (os)
            {
                try
                {
                    return Convert.ToInt32(os["ProductType"]);
                }
                catch
                {
                    return null;
                }
            }
        }

        return null;
    }

    // MpCmdRun -Scan exit semantics (observed + documented):
    // 0 = completed, no threats; 2 = completed, Defender found (and
    // owns the remediation of) threats; anything else = failure,
    // formatted as HRESULT when negative.
    public static (bool Completed, bool ThreatsReported, string Detail) InterpretExit(int exitCode) =>
        exitCode switch
        {
            0 => (true, false, "Defender completed the scan — no threats reported."),
            2 => (true, true,
                "Defender completed the scan and reported threats. Remediation is " +
                "Defender-owned (see Windows Security) — Sentinel changed nothing itself."),
            _ => (false, false, exitCode < 0
                ? $"Defender scan failed (HRESULT 0x{unchecked((uint)exitCode):X8})."
                : $"Defender scan failed (exit {exitCode})."),
        };

    public static string ValidateFolder(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Pick a folder or file to scan.", nameof(path));
        }

        string full = Path.GetFullPath(path);
        if (!Directory.Exists(full) && !File.Exists(full))
        {
            throw new ArgumentException($"Not found: {full}", nameof(path));
        }

        return full;
    }

    public static string? ResolveExe(string? overrideDir = null)
    {
        string dir = overrideDir
            ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Windows Defender");
        string exe = Path.Combine(dir, "MpCmdRun.exe");
        return File.Exists(exe) ? exe : null;
    }

    // Pure draft: validates the target, checks the tool exists,
    // and describes the exact command. Starts no process.
    public static DefenderScanPlan Plan(
        DefenderScanRequest request,
        string? exeOverrideDir = null,
        Func<int?>? productTypeReader = null)
    {
        string label = request.Kind switch
        {
            DefenderScanKind.Quick => "quick scan",
            DefenderScanKind.Full => "full scan",
            DefenderScanKind.Folder => "folder scan",
            DefenderScanKind.Offline => "offline scan (restarts this PC)",
            _ => "scan",
        };

        // Offline runs outside MpCmdRun: fixed command, platform
        // gate, restart acknowledgement at Confirm (not here).
        if (request.Kind == DefenderScanKind.Offline)
        {
            var (offlineExe, offlineArgs) = OfflineCommand();
            string offlineCommand = $"{offlineExe} {offlineArgs}";
            if (!OfflineSupported(productTypeReader))
            {
                return new DefenderScanPlan(
                    label, offlineCommand, false,
                    "Offline scan is not supported on this machine (Windows 10/11 client required). " +
                    "Nothing was started.");
            }

            return new DefenderScanPlan(
                label, offlineCommand, true,
                $"Planned: Defender {label} ({offlineCommand}). Confirm next — including the " +
                "restart acknowledgement. Nothing was started.");
        }

        string args;
        try
        {
            args = BuildArguments(request);
        }
        catch (ArgumentException ex)
        {
            return new DefenderScanPlan(
                label, "MpCmdRun.exe (invalid target)", false,
                $"{ex.Message} Nothing was started.");
        }

        string command = $"MpCmdRun.exe {args}";
        if (ResolveExe(exeOverrideDir) is null)
        {
            return new DefenderScanPlan(
                label, command, false,
                "Defender command-line tool not found on this PC. " +
                "Nothing was started.");
        }

        return new DefenderScanPlan(
            label, command, true,
            $"Planned: Defender {label} ({command}). Confirm next — nothing was started.");
    }

}

// T52: pure restore draft (same containment as the scan plan —
// validates the target, checks the tool exists, describes the
// exact command; starts no process).
public sealed record QuarantineRestoreRequest(string Name);

public sealed record QuarantineRestorePlan(
    string Name,
    string CommandLine,
    bool Ready,
    string Detail);

public static class QuarantineRestore
{
    public static QuarantineRestorePlan Plan(
        QuarantineRestoreRequest request, string? exeOverrideDir = null)
    {
        string name = request.Name?.Trim() ?? string.Empty;
        if (name.Length == 0)
        {
            return new QuarantineRestorePlan(
                string.Empty, "MpCmdRun.exe (no target)", false,
                "No quarantined item was selected. Nothing was started.");
        }

        // Restore identity is exact: the name must still be listed
        // when the executor re-reads current quarantine.
        string command = "-Restore -Name \"" + name.Replace("\"", string.Empty) + "\"";
        string commandLine = $"MpCmdRun.exe {command}";
        if (DefenderScan.ResolveExe(exeOverrideDir) is null)
        {
            return new QuarantineRestorePlan(
                name, commandLine, false,
                "Defender command-line tool not found on this PC. Nothing was started.");
        }

        return new QuarantineRestorePlan(
            name, commandLine, true,
            $"Planned: restore '{name}' ({commandLine}). Confirm next — nothing was started.");
    }
}
