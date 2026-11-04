using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;
using System.Text.RegularExpressions;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.Engine.Drivers;

// LIVE implementation of IDriverOps. Used ONLY in the VM dangerous-
// ops battery (elevated guest). Every call has a bounded timeout and
// stderr capture; unexpected COM/process failures surface as data
// (empty results + gaps carried by the caller), never as throws past
// the executor backstop. No method takes free-form shell text.
[SupportedOSPlatform("windows")]
public sealed partial class WindowsDriverOps : IDriverOps
{
    private readonly TimeSpan _timeout;

    public WindowsDriverOps(TimeSpan? timeout = null)
    {
        _timeout = timeout ?? TimeSpan.FromMinutes(20);
    }

    public DeviceStatus ReadDevice(string deviceId)
    {
        // SetupAPI is the presence/problem authority (same source as
        // Device Manager); WMI donates names and driver metadata.
        uint statusFlags = 0;
        uint problem = 0;
        string? setupName = null;
        bool found = false;
        try
        {
            var rows = DeviceSetupApi.TryEnumerate(out _);
            var row = rows?.FirstOrDefault(r =>
                string.Equals(r.Id, deviceId, StringComparison.OrdinalIgnoreCase));
            if (row is not null)
            {
                found = true;
                statusFlags = row.Value.Status;
                problem = row.Value.Problem;
                setupName = row.Value.Name;
            }
        }
        catch
        {
            // Fall through to not-present: refusing beats guessing.
        }

        if (!found)
        {
            return new DeviceStatus(false, 0, null, 0, null, null, null, []);
        }

        // Code 45 (disconnected/phantom) is not present for update
        // purposes — the hardware is gone.
        bool present = problem != 45;

        string? problemName = null;
        string? name = setupName;
        try
        {
            var problems = DriverCollector.CollectDeviceProblems();
            var match = problems.Records.FirstOrDefault(r =>
                string.Equals(r.DeviceId, deviceId, StringComparison.OrdinalIgnoreCase));
            if (match is not null)
            {
                problemName = match.ErrorName;
                problem = (uint)match.ErrorCode;
                name ??= match.Name;
            }
        }
        catch
        {
        }

        string? version = null;
        string? date = null;
        var hwids = new List<string>();
        try
        {
            var drivers = DriverCollector.Collect();
            var match = drivers.Records.FirstOrDefault(r =>
                name is not null &&
                string.Equals(r.DeviceName, name, StringComparison.OrdinalIgnoreCase));
            if (match is not null)
            {
                version = match.DriverVersion;
                date = match.DriverDate;
                if (!string.IsNullOrWhiteSpace(match.HardwareId))
                {
                    hwids.Add(match.HardwareId.Trim());
                }
            }
        }
        catch
        {
        }

        return new DeviceStatus(present, (int)problem, problemName, statusFlags,
            name, version, date, hwids);
    }

    public IReadOnlyList<DriverRecord> EnumInstalledDrivers()
    {
        try
        {
            return DriverCollector.Collect().Records;
        }
        catch
        {
            return [];
        }
    }

    public IReadOnlyList<StorePackage> EnumStore()
    {
        string text = RunPnPUtil("/enum-drivers");
        if (string.IsNullOrWhiteSpace(text))
        {
            return [];
        }

        try
        {
            return PnpUtilParser.ParseEnumDrivers(text);
        }
        catch
        {
            return [];
        }
    }

    public IReadOnlyList<DriverCandidate> SearchWindowsUpdate(
        string deviceId, string? deviceName, IReadOnlyList<string> hardwareIds)
    {
        _ = deviceId;
        try
        {
            return WindowsUpdateDrivers.Search(deviceName, hardwareIds);
        }
        catch
        {
            return [];
        }
    }

    public InstallResult InstallWindowsUpdate(string deviceId, string catalogueId)
    {
        if (string.IsNullOrWhiteSpace(catalogueId))
        {
            return new InstallResult(false, false, "Missing catalogue ID.");
        }

        try
        {
            return WindowsUpdateDrivers.Install(deviceId, catalogueId, _timeout);
        }
        catch (Exception ex)
        {
            return new InstallResult(false, false,
                $"Windows Update install failed ({ex.GetType().Name}): {Trim(ex.Message)}");
        }
    }

    public InstallResult InstallStorePackage(string publishedInf)
    {
        if (!StoreInfPattern().IsMatch(publishedInf ?? string.Empty))
        {
            return new InstallResult(false, false, "Refused: not an oemN.inf name.");
        }

        var (code, _, err) = RunPnPUtilSlow($"/add-driver \"{publishedInf}\" /install");
        if (code == 0)
        {
            return new InstallResult(true, false, $"{publishedInf} added and installed.");
        }

        return new InstallResult(false, false, $"pnputil failed (exit {code}): {Trim(err)}");
    }

    public OemScanSet ScanOemCatalogue()
    {
        var context = OemDetector.Detect();
        if (!context.DellDcuInstalled || string.IsNullOrWhiteSpace(context.DellDcuPath))
        {
            return new OemScanSet([], "No update-capable catalogue for this machine (Dell DCU not installed).");
        }

        var (ok, stdout, err) = Run(new ProcessStartInfo(context.DellDcuPath, "/scan")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        }, TimeSpan.FromMinutes(10));
        if (!ok)
        {
            return new OemScanSet([], $"Catalogue scan failed: {Trim(err)}");
        }

        var parsed = DcuParser.Parse(stdout);
        return new OemScanSet(parsed.Titles, parsed.RawSummary);
    }

    public InstallResult ApplyOemCatalogue()
    {
        var context = OemDetector.Detect();
        if (!context.DellDcuInstalled || string.IsNullOrWhiteSpace(context.DellDcuPath))
        {
            return new InstallResult(false, false, "No update-capable catalogue for this machine.");
        }

        // Fixed flags only: apply all pending, let DCU suspend
        // BitLocker itself when it needs a reboot. DCU applies the
        // whole set — the sheet confirms the set, never one device.
        var (ok, stdout, err) = Run(new ProcessStartInfo(
            context.DellDcuPath, "/applyUpdates -autoSuspendBitLocker=enable")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        }, _timeout);
        if (!ok)
        {
            return new InstallResult(false, false, $"Catalogue apply failed: {Trim(err)}");
        }

        bool reboot = stdout.Contains("reboot", StringComparison.OrdinalIgnoreCase);
        return new InstallResult(true, reboot,
            reboot ? "Catalogue apply complete — a reboot is pending."
                : "Catalogue apply complete.");
    }

    public bool IsNetworkAvailable()
    {
        try
        {
            return System.Net.NetworkInformation.NetworkInterface.GetIsNetworkAvailable();
        }
        catch
        {
            return false;
        }
    }

    // ---- process helpers ----

    private string RunPnPUtil(string args)
    {
        try
        {
            var (_, stdout, _) = Run(new ProcessStartInfo("pnputil.exe", args)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            }, TimeSpan.FromMinutes(5));
            return stdout;
        }
        catch
        {
            return string.Empty;
        }
    }

    private (int Code, string Stdout, string Stderr) RunPnPUtilSlow(string args)
    {
        var psi = new ProcessStartInfo("pnputil.exe", args)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        try
        {
            using var p = Process.Start(psi)!;
            var stdout = new StringBuilder();
            var stderr = new StringBuilder();
            p.OutputDataReceived += (_, e) => { if (e.Data is not null) { stdout.AppendLine(e.Data); } };
            p.ErrorDataReceived += (_, e) => { if (e.Data is not null) { stderr.AppendLine(e.Data); } };
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
            if (!p.WaitForExit(_timeout))
            {
                try { p.Kill(entireProcessTree: true); } catch { }
                return (-1, stdout.ToString(), "Timed out.");
            }

            return (p.ExitCode, stdout.ToString(), stderr.ToString());
        }
        catch (Exception ex)
        {
            return (-1, string.Empty, $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    private static (bool Ok, string Stdout, string Stderr) Run(ProcessStartInfo psi, TimeSpan timeout)
    {
        using var p = Process.Start(psi)!;
        // Async drains: a chatty tool must not deadlock on a full pipe.
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        p.OutputDataReceived += (_, e) => { if (e.Data is not null) { stdout.AppendLine(e.Data); } };
        p.ErrorDataReceived += (_, e) => { if (e.Data is not null) { stderr.AppendLine(e.Data); } };
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        if (!p.WaitForExit(timeout))
        {
            try { p.Kill(entireProcessTree: true); } catch { }
            return (false, stdout.ToString(), "Timed out.");
        }

        return (p.ExitCode == 0, stdout.ToString(), stderr.ToString());
    }

    private static string Trim(string s)
    {
        s = (s ?? string.Empty).Trim().ReplaceLineEndings(" ");
        return s.Length <= 300 ? s : s[..300];
    }

    [GeneratedRegex("^oem\\d{1,5}\\.inf$", RegexOptions.IgnoreCase)]
    private static partial Regex StoreInfPattern();
}
