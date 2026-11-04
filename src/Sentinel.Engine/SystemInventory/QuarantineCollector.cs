using System.Diagnostics;
using System.Text;

namespace Sentinel.Engine.SystemInventory;

// T52: CURRENT Defender quarantine (`MpCmdRun -Restore -ListAll`),
// read-only. Two honest boundaries: (1) even LISTING quarantine
// requires administrator (observed on host: "You need administrator
// privilege", hr 0x80070005) — unelevated reads fail with an
// ElevationRequired gap, never an empty list; (2) the exact list
// format is parsed defensively (key: value blocks keyed by Name)
// and confirmed against live output in the VM battery.
public static class QuarantineCollector
{
    public const int MaxEntries = 200;
    public const string Scope = "Defender quarantine (MpCmdRun -Restore -ListAll)";

    public static CollectionResult<QuarantineRecord> Collect(
        Func<(int ExitCode, string Output)>? listReader = null,
        Func<string?>? exeLocator = null)
    {
        var observed = DateTime.UtcNow;
        if (Environment.OSVersion.Platform != PlatformID.Win32NT && listReader is null)
        {
            return CollectionResult<QuarantineRecord>.Fail(Scope, "WindowsOnly");
        }

        if (listReader is null)
        {
            string? exe = exeLocator is not null ? exeLocator() : DefenderScan.ResolveExe();
            if (string.IsNullOrWhiteSpace(exe))
            {
                return CollectionResult<QuarantineRecord>.Fail(
                    Scope, "ToolMissing", "MpCmdRun.exe not found on this PC.");
            }
        }

        (int ExitCode, string Output) run;
        try
        {
            run = listReader is not null
                ? listReader()
                : RunList(exeLocator is not null ? exeLocator() : DefenderScan.ResolveExe());
        }
        catch (Exception ex)
        {
            return CollectionResult<QuarantineRecord>.Fail(
                Scope, ex.GetType().Name, Trim(ex.Message));
        }

        if (IsAccessDenied(run.Output))
        {
            return CollectionResult<QuarantineRecord>.Fail(
                Scope, "ElevationRequired",
                "Defender quarantine is unreadable without administrator rights.");
        }

        if (run.ExitCode != 0)
        {
            return CollectionResult<QuarantineRecord>.Fail(
                Scope, "ListFailed", $"MpCmdRun exited {run.ExitCode}.");
        }

        var (records, unparsed) = ParseList(run.Output, MaxEntries);
        var gaps = new List<CollectionGap>();
        if (unparsed > 0)
        {
            gaps.Add(new CollectionGap(Scope, "UnparsedBlocks", unparsed.ToString()));
        }

        bool truncated = records.Count >= MaxEntries;
        if (truncated)
        {
            gaps.Add(new CollectionGap(Scope, "Truncated", $"kept first {MaxEntries}"));
        }

        var status = gaps.Count == 0 ? CollectionStatus.Success : CollectionStatus.Partial;
        return new CollectionResult<QuarantineRecord>(
            status, records, Scope, observed, gaps, truncated);
    }

    internal static (int ExitCode, string Output) RunList(string? exe)
    {
        if (string.IsNullOrWhiteSpace(exe))
        {
            throw new InvalidOperationException("MpCmdRun.exe not found on this PC.");
        }

        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = exe,
            Arguments = "-Restore -ListAll",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            // Default console decoding: MpCmdRun writes OEM text.
        }) ?? throw new InvalidOperationException("MpCmdRun did not start.");
        var stdout = new StringBuilder();
        proc.OutputDataReceived += (_, e) => { if (e.Data is not null) { stdout.AppendLine(e.Data); } };
        proc.BeginOutputReadLine();
        string stderr = proc.StandardError.ReadToEnd();
        if (!proc.WaitForExit(TimeSpan.FromMinutes(2)))
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException("MpCmdRun -Restore -ListAll timed out.");
        }

        return (proc.ExitCode, stdout.ToString() + stderr);
    }

    internal static bool IsAccessDenied(string output) =>
        output.Contains("administrator privilege", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("0x80070005", StringComparison.OrdinalIgnoreCase);

    // Defensive block parse: blank-line separated `Key: value`
    // groups; a block with a Name-ish key is an entry. Unknown
    // keys are kept in Raw, never dropped silently.
    internal static (IReadOnlyList<QuarantineRecord> Records, int Unparsed) ParseList(
        string output, int limit)
    {
        var records = new List<QuarantineRecord>();
        int unparsed = 0;
        var block = new List<string>();

        void Flush()
        {
            if (block.Count == 0)
            {
                return;
            }

            var record = ParseBlock(block);
            if (record is null)
            {
                unparsed++;
            }
            else if (records.Count < limit)
            {
                records.Add(record);
            }

            block.Clear();
        }

        foreach (string line in output.Split('\n'))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                Flush();
            }
            else
            {
                block.Add(line.Trim());
            }
        }

        Flush();
        return (records, unparsed);
    }

    internal static QuarantineRecord? ParseBlock(IReadOnlyList<string> lines)
    {
        string? name = null;
        string? threat = null;
        string? path = null;
        string? detected = null;
        foreach (string line in lines)
        {
            int colon = line.IndexOf(':');
            if (colon <= 0)
            {
                continue;
            }

            string key = line[..colon].Trim();
            string value = line[(colon + 1)..].Trim();
            if (value.Length == 0)
            {
                continue;
            }

            if (IsNameKey(key))
            {
                name ??= value;
            }
            else if (key.Contains("threat", StringComparison.OrdinalIgnoreCase) && threat is null)
            {
                threat = value;
            }
            else if (IsPathKey(key) && path is null)
            {
                path = value;
            }
            else if (IsDetectedKey(key) && detected is null)
            {
                detected = value;
            }
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            return null;
        }

        return new QuarantineRecord(name, threat, path, detected, string.Join("\n", lines));
    }

    private static bool IsNameKey(string key) =>
        key.Equals("Name", StringComparison.OrdinalIgnoreCase) ||
        key.Equals("Threat Name", StringComparison.OrdinalIgnoreCase) ||
        key.Equals("ThreatName", StringComparison.OrdinalIgnoreCase);

    private static bool IsPathKey(string key) =>
        key.Contains("path", StringComparison.OrdinalIgnoreCase) ||
        key.Contains("file", StringComparison.OrdinalIgnoreCase) ||
        key.Contains("resource", StringComparison.OrdinalIgnoreCase);

    private static bool IsDetectedKey(string key) =>
        key.Contains("detect", StringComparison.OrdinalIgnoreCase) ||
        key.Contains("date", StringComparison.OrdinalIgnoreCase) ||
        key.Contains("time", StringComparison.OrdinalIgnoreCase);

    private static string Trim(string message, int max = 200) =>
        message.Length <= max ? message : message[..max] + "…";
}
