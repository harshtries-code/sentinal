using System.Diagnostics;

namespace Sentinel.Engine.SystemInventory;

// Priority verdict for ONE process (R5, 04 Phase 2 "live
// watcher"): the read-only evidence a mid-scan plant gets —
// process identity + local static file evidence (SHA-256 +
// Authenticode, no network) + an honest label. ElapsedMs is the
// measured verdict time (03 §5 target: < 3s to a verdict card).
//
// Vocabulary discipline (05, M4): "Unverified" is NEVER a malware
// verdict — unsigned includes every freshly built binary. Labels
// say what was OBSERVED, never what is concluded.
public sealed record ProcessVerdict(
    int Pid,
    string Name,
    string? ExePath,
    string? Company,
    string Verdict,
    string Detail,
    string? Sha256,
    string? SignerSubject,
    long ElapsedMs);

public static class PriorityProcessCheck
{
    // Checks ONE pid. Never throws for process states (exited,
    // protected, pathless): those are verdicts, not errors.
    public static ProcessVerdict Check(int pid)
    {
        var sw = Stopwatch.StartNew();
        ProcessRecord? proc = Find(pid);
        if (proc is null)
        {
            sw.Stop();
            return new ProcessVerdict(
                pid, "unknown", null, null, "NotFound",
                "No such process — it exited before the check ran.",
                null, null, sw.ElapsedMilliseconds);
        }

        if (string.IsNullOrWhiteSpace(proc.Path))
        {
            sw.Stop();
            return new ProcessVerdict(
                proc.Id, proc.Name, null, proc.Company, "NoPath",
                "No executable path visible (system or protected process).",
                null, null, sw.ElapsedMilliseconds);
        }

        var evidence = StaticEvidenceCollector.CheckFiles([proc.Path], maxFiles: 1);
        var file = evidence.Records.FirstOrDefault();
        sw.Stop();
        if (file is null || !file.Exists)
        {
            return new ProcessVerdict(
                proc.Id, proc.Name, proc.Path, proc.Company, "ExeNotFound",
                "The executable is no longer on disk (" +
                    (file?.Detail ?? "no record") + ").",
                null, null, sw.ElapsedMilliseconds);
        }

        if (file.Signed && !string.IsNullOrWhiteSpace(file.SignerSubject))
        {
            return new ProcessVerdict(
                proc.Id, proc.Name, proc.Path, proc.Company, "SignedPublisher",
                "Authenticode-verified, signed by " + file.SignerSubject + ".",
                file.Sha256, file.SignerSubject, sw.ElapsedMilliseconds);
        }

        string who = string.IsNullOrWhiteSpace(proc.Company)
            ? "unknown company"
            : proc.Company;
        return new ProcessVerdict(
            proc.Id, proc.Name, proc.Path, proc.Company, "Unverified",
            "Not Authenticode-verified (" + who + ") — check first. " +
                "Unsigned is common and NOT a malware verdict.",
            file.Sha256, null, sw.ElapsedMilliseconds);
    }

    // Direct single-PID read (O(1)): a priority check must not
    // enumerate all ~200 processes first — that cost IS the bulk
    // lane. Same per-process semantics as ProcessCollector (name,
    // MainModule path, version company, working set); anything
    // unreadable degrades the verdict, never throws.
    private static ProcessRecord? Find(int pid)
    {
        Process proc;
        try
        {
            proc = Process.GetProcessById(pid);
        }
        catch
        {
            return null; // No such pid, or it exited mid-check.
        }

        using (proc)
        {
            string name;
            try
            {
                name = proc.ProcessName;
            }
            catch
            {
                return null;
            }

            string? path = null;
            DateTime? started = null;
            long ws = 0;
            try
            {
                ws = proc.WorkingSet64;
                path = proc.MainModule?.FileName;
                started = proc.StartTime.ToUniversalTime();
            }
            catch
            {
                // Protected/system process: row survives, detail lost.
            }

            string? company = null;
            string? product = null;
            if (path is not null)
            {
                try
                {
                    var info = FileVersionInfo.GetVersionInfo(path);
                    company = BlankToNull(info.CompanyName);
                    product = BlankToNull(info.ProductName);
                }
                catch
                {
                    // No version resource; fine.
                }
            }

            return new ProcessRecord(pid, name, path, company, product, started, ws);
        }
    }

    private static string? BlankToNull(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }
}
