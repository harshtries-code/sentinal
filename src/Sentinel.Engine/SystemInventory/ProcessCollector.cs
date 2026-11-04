using System.Diagnostics;

namespace Sentinel.Engine.SystemInventory;

// READ-ONLY: snapshot of running processes. No process is touched.
// Rows with reduced detail (protected processes, exited races) are
// counted in gaps so "0 detail rows" never looks like full coverage.
public static class ProcessCollector
{
    private const string Scope = "Running processes (id, name, path, company, start, working set)";

    public static CollectionResult<ProcessRecord> Collect()
    {
        var observed = DateTime.UtcNow;
        var result = new List<ProcessRecord>();
        int reduced = 0;
        int skipped = 0;
        // T51: one ToolHelp snapshot for the whole parent table
        // (empty off-Windows — parents read unknown, not absent).
        var parents = ProcessParentMap.Collect();
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                string name;
                try
                {
                    name = p.ProcessName;
                }
                catch
                {
                    skipped++; // Exited mid-snapshot.
                    continue;
                }

                string? path = null;
                DateTime? started = null;
                long ws = 0;
                bool fullDetail = true;
                try
                {
                    ws = p.WorkingSet64;
                    path = p.MainModule?.FileName;
                    started = p.StartTime.ToUniversalTime();
                }
                catch
                {
                    // Protected/system process: keep the row, lose the detail.
                    fullDetail = false;
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
                else
                {
                    fullDetail = false;
                }

                if (!fullDetail)
                {
                    reduced++;
                }

                int? parentId = null;
                string? parentName = null;
                if (parents.TryGetValue(p.Id, out var parent) && parent.ParentId != 0)
                {
                    parentId = parent.ParentId;
                    parentName = parents.TryGetValue(parent.ParentId, out var grand)
                        ? BlankToNull(grand.Exe)
                        : null;
                }

                result.Add(new ProcessRecord(p.Id, name, path, company, product, started, ws,
                    parentId, parentName));
                p.Dispose();
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return CollectionResult<ProcessRecord>.Fail(Scope, "SnapshotFailed", ex.GetType().Name);
        }

        var gaps = new List<CollectionGap>();
        if (reduced > 0)
        {
            gaps.Add(new CollectionGap(Scope, "ReducedDetailRows", reduced.ToString()));
        }

        if (skipped > 0)
        {
            gaps.Add(new CollectionGap(Scope, "ExitedMidSnapshot", skipped.ToString()));
        }

        var status = gaps.Count == 0 ? CollectionStatus.Success : CollectionStatus.Partial;
        return new CollectionResult<ProcessRecord>(status, result, Scope, observed, gaps, false);
    }

    // P21: the watcher's sweep snapshot — PIDs ONLY. One batched
    // enumeration, zero per-process queries: even StartTime reads
    // cost ~1ms each on NEM (~150ms/sweep), which alone would blow
    // the watch's own ≤2% budget at a 2s cadence (measured
    // 2026-11-04 in-guest: id-only 80ms, +name 59ms, +start 114ms,
    // path ~29ms each, PowerShell-timed). Name/start/path bind
    // per arrival via TryResolve, where the cost lands on events,
    // not on every sweep.
    public static CollectionResult<ProcessRecord> CollectLight()
    {
        var observed = DateTime.UtcNow;
        var result = new List<ProcessRecord>();
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                // Id is captured by the batched enumeration itself:
                // no handle, no query, no per-process cost.
                result.Add(new ProcessRecord(p.Id, string.Empty, null, null, null, null, 0));
                p.Dispose();
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return CollectionResult<ProcessRecord>.Fail(Scope, "SnapshotFailed", ex.GetType().Name);
        }

        return CollectionResult<ProcessRecord>.Ok(result, Scope);
    }

    // P27: CPU% for the top-N memory processes, measured over a
    // short bounded window. Two TotalProcessorTime reads per
    // candidate (≤50 queries, page-refresh cadence only — never the
    // watcher's 2s sweep). Exited/protected resamples come back
    // null and render as "—". Percent is of total machine capacity
    // like every other CPU number in the app.
    public static IReadOnlyList<ProcessCpuSample> CollectTopCpu(int topN = 25, int windowMs = 250)
    {
        topN = Math.Clamp(topN, 1, 100);
        windowMs = Math.Clamp(windowMs, 50, 2000);
        var candidates = Collect().Records
            .OrderByDescending(p => p.WorkingSetBytes)
            .Take(topN)
            .ToList();
        var first = new Dictionary<int, (string Name, TimeSpan Cpu)>();
        foreach (var c in candidates)
        {
            try
            {
                using var p = Process.GetProcessById(c.Id);
                first[c.Id] = (c.Name, p.TotalProcessorTime);
            }
            catch
            {
                // Exited between snapshot and first read: the
                // resample below reports it as null.
            }
        }

        Thread.Sleep(windowMs);
        var wallMs = (double)windowMs;
        int cores = Math.Max(1, Environment.ProcessorCount);
        var rows = new List<ProcessCpuSample>();
        foreach (var c in candidates)
        {
            double? percent = null;
            if (first.TryGetValue(c.Id, out var start))
            {
                try
                {
                    using var p = Process.GetProcessById(c.Id);
                    var delta = (p.TotalProcessorTime - start.Cpu).TotalMilliseconds;
                    percent = Math.Max(0, delta / (wallMs * cores) * 100.0);
                }
                catch
                {
                    // Exited or protected on resample: null.
                }
            }

            rows.Add(new ProcessCpuSample(c.Id, c.Name, percent));
        }

        return rows;
    }

    // P21: per-arrival identity binding for the watcher — one
    // handle, one name/start/path read. Null when the process
    // exited before binding; partial (name only, or name+start)
    // for protected processes — never throws.
    public static ProcessIdentity? TryResolve(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            string name;
            try
            {
                name = proc.ProcessName;
            }
            catch
            {
                return null;
            }

            DateTime? started = null;
            try
            {
                started = proc.StartTime.ToUniversalTime();
            }
            catch
            {
            }

            string? path = null;
            try
            {
                path = proc.MainModule?.FileName;
            }
            catch
            {
            }

            return new ProcessIdentity(pid, name, started, path);
        }
        catch
        {
            return null;
        }
    }

    private static string? BlankToNull(string? value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }
}
