using System.Diagnostics;
using System.Text.RegularExpressions;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.Engine.CrashDoctor;

// One dump's fate (P24, 07 Q4): file facts always, analyzed
// metadata only when Debugging Tools are present. Raw dump bytes
// never leave this method — cdb reads them locally and only the
// parsed code/module/stack excerpt returns.
public sealed record MinidumpReport(
    string Name,
    long? SizeBytes,
    DateTime? ModifiedUtc,
    uint? BugCheckCode,
    string? BugCheckName,
    string? Module,
    string? StackHead,
    string Status,
    string? Note);

public static partial class MinidumpInspector
{
    public const int DefaultMaxDumps = 5;
    public const int AnalyzeTimeoutSeconds = 180;
    public const int StackFrameCap = 10;
    public const int StackTextCap = 2000;

    // Newest first, bounded. Never throws: every failure mode is a
    // status/note on a report or a collection gap.
    public static CollectionResult<MinidumpReport> Inspect(int maxDumps = DefaultMaxDumps)
    {
        string windows;
        try
        {
            windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        }
        catch
        {
            return CollectionResult<MinidumpReport>.Fail(
                "Minidump metadata (cdb !analyze, local only)",
                "WindowsDirUnknown", null);
        }

        return InspectWith(windows, FindCdb(), maxDumps);
    }

    // Test seam: the guest session cannot plant dumps (no elevation),
    // so listing + ToolsMissing + cap behavior prove out here against
    // a stand-in Windows dir. Production always passes the real one.
    internal static CollectionResult<MinidumpReport> InspectWith(
        string windowsDir, string? cdb, int maxDumps = DefaultMaxDumps)
    {
        const string scope = "Minidump metadata (cdb !analyze, local only)";
        var observed = DateTime.UtcNow;
        var gaps = new List<CollectionGap>();
        var dumps = ListDumps(gaps, windowsDir);
        if (dumps.Count == 0)
        {
            return new CollectionResult<MinidumpReport>(
                CollectionStatus.Success, [], scope + " — no dumps present",
                observed, gaps, false);
        }

        var reports = new List<MinidumpReport>();
        foreach (var dump in dumps
            .OrderByDescending(d => d.ModifiedUtc ?? DateTime.MinValue)
            .Take(Math.Max(1, maxDumps)))
        {
            if (cdb is null)
            {
                reports.Add(new MinidumpReport(
                    dump.Name, dump.SizeBytes, dump.ModifiedUtc,
                    null, null, null, null, "ToolsMissing",
                    "Debugging Tools for Windows (cdb) are not installed — " +
                    "showing the dump file list only. Event Log + knowledge " +
                    "pack still apply."));
                continue;
            }

            reports.Add(AnalyzeOne(cdb, dump));
        }

        bool truncated = dumps.Count > reports.Count;
        return new CollectionResult<MinidumpReport>(
            gaps.Count == 0 ? CollectionStatus.Success : CollectionStatus.Partial,
            reports, scope, observed, gaps, truncated);
    }

    internal sealed record DumpFile(string Name, string FullPath, long? SizeBytes, DateTime? ModifiedUtc);

    internal static IReadOnlyList<DumpFile> ListDumps(List<CollectionGap> gaps)
    {
        string windows;
        try
        {
            windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        }
        catch
        {
            gaps.Add(new CollectionGap("Minidump", "WindowsDirUnknown", null));
            return [];
        }

        return ListDumps(gaps, windows);
    }

    internal static IReadOnlyList<DumpFile> ListDumps(List<CollectionGap> gaps, string windowsDir)
    {
        var dumps = new List<DumpFile>();
        string dir = Path.Combine(windowsDir, "Minidump");
        string[] files;
        try
        {
            files = Directory.Exists(dir) ? Directory.GetFiles(dir, "*.dmp") : [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            gaps.Add(new CollectionGap("Minidump", "DumpDirUnreadable", ex.GetType().Name));
            files = [];
        }

        var candidates = files.ToList();
        string memory = Path.Combine(windowsDir, "MEMORY.DMP");
        try
        {
            if (File.Exists(memory))
            {
                candidates.Add(memory);
            }
        }
        catch
        {
            // An unstatable MEMORY.DMP is absence, not evidence.
        }

        foreach (string path in candidates)
        {
            long? size = null;
            DateTime? modified = null;
            try
            {
                var info = new FileInfo(path);
                if (info.Exists)
                {
                    size = info.Length;
                    modified = info.LastWriteTimeUtc;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                gaps.Add(new CollectionGap("Minidump", "DumpStatFailed", ex.GetType().Name));
            }

            dumps.Add(new DumpFile(
                Path.GetFileName(path), path, size, modified));
        }

        return dumps;
    }

    // Debugging Tools install locations + PATH. Existence only —
    // never executed here, so a remembered path is still re-checked
    // at analyze time (TOCTOU: the file may vanish between calls).
    internal static string? FindCdb()
    {
        var candidates = new List<string>();
        string pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        foreach (string root in new[] { pf86, pf })
        {
            if (!string.IsNullOrWhiteSpace(root))
            {
                candidates.Add(Path.Combine(
                    root, @"Windows Kits\10\Debuggers\x64\cdb.exe"));
            }
        }

        string? pathEnv = Environment.GetEnvironmentVariable("PATH");
        if (!string.IsNullOrEmpty(pathEnv))
        {
            foreach (string dir in pathEnv.Split(Path.PathSeparator))
            {
                string trimmed = dir.Trim().Trim('"');
                if (trimmed.Length > 0)
                {
                    candidates.Add(Path.Combine(trimmed, "cdb.exe"));
                }
            }
        }

        foreach (string candidate in candidates)
        {
            try
            {
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
            catch
            {
                // Unstatable candidate: keep looking.
            }
        }

        return null;
    }

    private static MinidumpReport AnalyzeOne(string cdb, DumpFile dump)
    {
        string output;
        try
        {
            if (!File.Exists(cdb) || !File.Exists(dump.FullPath))
            {
                return new MinidumpReport(
                    dump.Name, dump.SizeBytes, dump.ModifiedUtc,
                    null, null, null, null, "AnalyzeFailed",
                    "Tool or dump vanished before analysis started.");
            }

            // Local symbol cache under temp (OS-cleaned); first
            // analysis of a build may download from the Microsoft
            // symbol server, bounded by the per-dump timeout.
            string cache = Path.Combine(Path.GetTempPath(), "sentinel-symbols");
            var start = new ProcessStartInfo
            {
                FileName = cdb,
                Arguments = $"-z \"{dump.FullPath}\" " +
                    $"-y \"srv*{cache}*https://msdl.microsoft.com/download/symbols\" " +
                    "-c \"!analyze -v;q\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            using var process = Process.Start(start);
            if (process is null)
            {
                return new MinidumpReport(
                    dump.Name, dump.SizeBytes, dump.ModifiedUtc,
                    null, null, null, null, "AnalyzeFailed",
                    "cdb would not start.");
            }

            // Drain both pipes on background readers: !analyze -v
            // output overflows the pipe buffer, which would wedge
            // cdb if we only waited for exit first.
            var outTask = Task.Run(() => process.StandardOutput.ReadToEnd());
            var errTask = Task.Run(() => process.StandardError.ReadToEnd());
            if (!process.WaitForExit(TimeSpan.FromSeconds(AnalyzeTimeoutSeconds)))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch
                {
                }

                return new MinidumpReport(
                    dump.Name, dump.SizeBytes, dump.ModifiedUtc,
                    null, null, null, null, "AnalyzeFailed",
                    $"Analysis exceeded the {AnalyzeTimeoutSeconds}s bound " +
                    "(killed; often first-run symbol download).");
            }

            if (!Task.WaitAll([outTask, errTask], TimeSpan.FromSeconds(30)))
            {
                return new MinidumpReport(
                    dump.Name, dump.SizeBytes, dump.ModifiedUtc,
                    null, null, null, null, "AnalyzeFailed",
                    "cdb exited but its output could not be drained.");
            }

            output = outTask.Result;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return new MinidumpReport(
                dump.Name, dump.SizeBytes, dump.ModifiedUtc,
                null, null, null, null, "AnalyzeFailed",
                "cdb failed: " + ex.GetType().Name);
        }

        var parsed = ParseAnalyzeOutput(output);
        if (parsed is null)
        {
            return new MinidumpReport(
                dump.Name, dump.SizeBytes, dump.ModifiedUtc,
                null, null, null, null, "AnalyzeFailed",
                "cdb ran but its output had no parsable bug-check block.");
        }

        return new MinidumpReport(
            dump.Name, dump.SizeBytes, dump.ModifiedUtc,
            parsed.Code, parsed.Name, parsed.Module, parsed.StackHead,
            "Analyzed", null);
    }

    internal sealed record ParsedAnalysis(
        uint Code, string? Name, string? Module, string? StackHead);

    // Pure: !analyze -v text in, code/module/stack out. Anything
    // unparseable yields null (AnalyzeFailed), never a guess.
    internal static ParsedAnalysis? ParseAnalyzeOutput(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        uint? code = null;
        string? name = null;
        // Title line first: "DRIVER_IRQL_NOT_LESS_OR_EQUAL (d1)".
        Match title = BugCheckTitlePattern().Match(text);
        if (title.Success)
        {
            string candidate = title.Groups[1].Value.Trim();
            if (candidate.Length is >= 3 and <= 64)
            {
                name = candidate;
            }

            if (uint.TryParse(
                title.Groups[2].Value,
                System.Globalization.NumberStyles.HexNumber, null, out uint titleCode))
            {
                code = titleCode;
            }
        }

        foreach (Match m in BugCheckPattern().Matches(text))
        {
            string hex = m.Groups[1].Value;
            if (uint.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out uint parsed))
            {
                code = parsed;
                string candidate = m.Groups.Count > 2 ? m.Groups[2].Value.Trim() : string.Empty;
                if (!string.IsNullOrWhiteSpace(candidate) && candidate.Length <= 64)
                {
                    name = candidate;
                }

                break;
            }
        }

        // Fallback shape when the header line is absent.
        if (code is null)
        {
            Match bare = BugCheckCodePattern().Match(text);
            if (bare.Success
                && uint.TryParse(
                    bare.Groups[1].Value,
                    System.Globalization.NumberStyles.HexNumber, null, out uint bareParsed))
            {
                code = bareParsed;
            }
        }

        if (code is null)
        {
            return null;
        }

        string? module = null;
        Match mm = ModulePattern().Match(text);
        if (mm.Success)
        {
            string candidate = mm.Groups[1].Value.Trim();
            if (candidate.Length is >= 3 and <= 64)
            {
                module = candidate;
            }
        }

        string? stack = ParseStackHead(text);
        return new ParsedAnalysis(code.Value, name, module, stack);
    }

    private static string? ParseStackHead(string text)
    {
        int at = text.IndexOf("STACK_TEXT:", StringComparison.Ordinal);
        if (at < 0)
        {
            return null;
        }

        var frames = new List<string>();
        foreach (string raw in text[(at + "STACK_TEXT:".Length)..].Split('\n'))
        {
            string line = raw.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (line.StartsWith("STACK_COMMAND", StringComparison.Ordinal)
                || line.StartsWith("SYMBOL_NAME", StringComparison.Ordinal)
                || line.StartsWith("FOLLOWUP_", StringComparison.Ordinal))
            {
                break;
            }

            frames.Add(line.Length > 200 ? line[..200] : line);
            if (frames.Count >= StackFrameCap)
            {
                break;
            }
        }

        if (frames.Count == 0)
        {
            return null;
        }

        string joined = string.Join("\n", frames);
        return joined.Length > StackTextCap ? joined[..StackTextCap] : joined;
    }

    // "BugCheck 139, {3, ...}" / "BUGCHECK_CODE:  139" /
    // "BugCheck D1, {…} (DRIVER_IRQL_NOT_LESS_OR_EQUAL)" shapes.
    [GeneratedRegex(@"BugCheck\s+([0-9A-Fa-f]+)(?:\s*\(\s*([A-Z0-9_]+)\s*\))?", RegexOptions.IgnoreCase)]
    private static partial Regex BugCheckPattern();

    [GeneratedRegex(@"^([A-Z][A-Z0-9_]{2,63})\s+\(([0-9A-Fa-f]+)\)", RegexOptions.Multiline)]
    private static partial Regex BugCheckTitlePattern();

    [GeneratedRegex(@"BUGCHECK_CODE:\s*([0-9A-Fa-f]+)", RegexOptions.IgnoreCase)]
    private static partial Regex BugCheckCodePattern();

    [GeneratedRegex(@"MODULE_NAME:\s*(\S+)", RegexOptions.IgnoreCase)]
    private static partial Regex ModulePattern();
}
