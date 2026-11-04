using System.Collections.Concurrent;
using System.Diagnostics;
using Sentinel.Engine.Scan;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.Engine.Watch;

// Automatic priority watching (P21, 03 §4): discovers new processes
// and new/changed executables while the app is open, verdicts them
// through the R5 priority path, and publishes cards. In-process,
// one dedicated BelowNormal thread + OS folder callbacks; Stop()
// joins the thread and releases every folder handle, so closing
// the app leaves nothing behind (closed = 0MB).
//
// Honesty rules: processes already running at Start are BASELINED,
// never carded (cards mean "appeared while you watched"); excluded-
// from-inspection paths (A11) are skipped with a counter, never
// carded; a reused PID is a new identity, verified by start time;
// storms coalesce per-exe with a counter, never flood.
public sealed class ProcessWatcher : IDisposable
{
    private readonly IProcessSnapshotSource _snapshots;
    private readonly IFileEventSource _files;
    private readonly WatchOptions _options;
    private readonly Func<IReadOnlyList<string>> _excludedProvider;
    private readonly Func<int, ProcessIdentity?> _identityResolver;
    private Thread? _thread;
    private readonly ManualResetEventSlim _wake = new(false);
    private readonly ConcurrentQueue<string> _fileQueue = new();
    private readonly object _gate = new();
    private readonly Dictionary<int, DateTime?> _knownPids = new();
    private readonly HashSet<int> _unboundCarded = new();
    private readonly Dictionary<string, int> _coalescedByExe = new(StringComparer.OrdinalIgnoreCase);
    private readonly SnoozeTracker _snooze = new();
    private readonly List<string> _delta = new();
    private DateTime _lastDeltaUtc = DateTime.UtcNow;
    private bool _baselined;
    private bool _running;
    private bool _disposed;

    // Stats (all under _gate).
    private long _sweeps;
    private long _sweepsFailed;
    private long _eventsSeen;
    private long _cardsPublished;
    private long _coalesced;
    private long _droppedOverCap;
    private long _excludedSkipped;
    private long _missedFolderEvents;
    private long _deltaPathsQueued;
    private long _activeMs;
    private DateTime _lastSweepUtc;
    private long _lastSweepMs;

    public ProcessWatcher(
        IProcessSnapshotSource snapshots,
        IFileEventSource files,
        WatchOptions? options = null,
        Func<IReadOnlyList<string>>? excludedProvider = null,
        Func<int, ProcessIdentity?>? identityResolver = null)
    {
        _snapshots = snapshots;
        _files = files;
        _options = options ?? WatchOptions.Default([], []);
        _excludedProvider = excludedProvider ?? (() => []);
        _identityResolver = identityResolver ?? ProcessCollector.TryResolve;
        _files.FileAppeared += OnFileAppeared;
        _files.EventsMissed += OnEventsMissed;
    }

    public event Action<WatchCard>? CardPublished;

    public event Action<IReadOnlyList<string>>? DeltaReady;

    public bool IsRunning
    {
        get
        {
            lock (_gate)
            {
                return _running;
            }
        }
    }

    public WatchStats Stats
    {
        get
        {
            lock (_gate)
            {
                return new WatchStats(
                    _sweeps, _eventsSeen, _cardsPublished, _coalesced,
                    _droppedOverCap, _excludedSkipped, _missedFolderEvents,
                    _deltaPathsQueued, _activeMs, _lastSweepUtc,
                    _lastSweepMs, (int)Math.Min(_cardsPublished, int.MaxValue));
            }
        }
    }

    public void Start()
    {
        Thread thread;
        lock (_gate)
        {
            if (_running || _disposed)
            {
                return;
            }

            // A Thread starts once: every Start builds a fresh one
            // so the setting toggle can restart the watch.
            thread = new Thread(Loop)
            {
                IsBackground = true,
                Name = "Sentinel.Watch",
                Priority = ThreadPriority.BelowNormal,
            };
            _thread = thread;
            _running = true;
        }

        _files.Start();
        thread.Start();
    }

    // Stops the folder callbacks, then joins the sweep thread.
    // Returns false only when the join timed out (the thread is a
    // background thread, so even then the process can still exit).
    public bool Stop(TimeSpan? timeout = null)
    {
        Thread? thread;
        lock (_gate)
        {
            if (!_running)
            {
                return true;
            }

            _running = false;
            thread = _thread;
            _thread = null;
        }

        try
        {
            _files.Stop();
        }
        catch
        {
        }

        _wake.Set();
        bool joined = thread?.Join(timeout ?? TimeSpan.FromSeconds(5)) ?? true;
        // Pending deltas die with the session: flushing here would
        // slow shutdown for work the next scan covers anyway.
        lock (_gate)
        {
            _delta.Clear();
        }

        return joined;
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        Stop();
        _files.FileAppeared -= OnFileAppeared;
        _files.EventsMissed -= OnEventsMissed;
        try
        {
            _files.Dispose();
        }
        catch
        {
        }

        _wake.Dispose();
    }

    private void OnFileAppeared(string path)
    {
        _fileQueue.Enqueue(path);
        _wake.Set();
    }

    private void OnEventsMissed()
    {
        lock (_gate)
        {
            _missedFolderEvents++;
        }
    }

    private void Loop()
    {
        while (true)
        {
            lock (_gate)
            {
                if (!_running)
                {
                    return;
                }
            }

            var sw = Stopwatch.StartNew();
            try
            {
                Sweep();
            }
            catch
            {
                lock (_gate)
                {
                    _sweepsFailed++;
                }
            }
            finally
            {
                sw.Stop();
                lock (_gate)
                {
                    _activeMs += sw.ElapsedMilliseconds;
                    _lastSweepMs = sw.ElapsedMilliseconds;
                    _lastSweepUtc = DateTime.UtcNow;
                }
            }

            _wake.Wait(_options.SweepInterval);
            _wake.Reset();
        }
    }

    private void Sweep()
    {
        DateTime now = DateTime.UtcNow;
        List<string> canonicalExcluded;
        try
        {
            canonicalExcluded = (_excludedProvider() ?? [])
                .Select(ScopePaths.CanonicalRoot)
                .Where(x => x is not null)
                .Select(x => x!)
                .ToList();
        }
        catch
        {
            canonicalExcluded = [];
        }

        bool IsExcluded(string? path) =>
            path is not null
            && ScopePaths.CanonicalPath(path) is string full
            && canonicalExcluded.Any(x => ScopePaths.IsUnder(full, x));

        IReadOnlyList<ProcessRecord> snapshot;
        try
        {
            snapshot = _snapshots.Snapshot();
        }
        catch
        {
            snapshot = [];
        }

        // PID-diff only: rows carry no name/start/path (CollectLight).
        // Identity binds per arrival inside VerdictProcess, where
        // the cost lands on events instead of every sweep.
        var arrivals = new List<int>();
        var alive = new HashSet<int>();
        bool firstSweep;
        lock (_gate)
        {
            firstSweep = !_baselined;
            _sweeps++;
            foreach (var proc in snapshot)
            {
                alive.Add(proc.Id);
                if (!_knownPids.ContainsKey(proc.Id))
                {
                    // Stamped when PROCESSED below, not here: an
                    // arrival dropped over the sweep cap stays
                    // unknown and retries next sweep (backpressure,
                    // never loss). The baseline sweep stamps all.
                    if (firstSweep)
                    {
                        _knownPids[proc.Id] = null;
                    }
                    else
                    {
                        arrivals.Add(proc.Id);
                    }
                }
            }

            // Exit cleanup: forget dead PIDs so the maps stay
            // session-sized. Snooze keys are NOT forgotten (01 §5.8
            // loop prevention survives death); the prune below is
            // the size backstop instead.
            foreach (var pid in _knownPids.Keys.Where(p => !alive.Contains(p)).ToList())
            {
                _knownPids.Remove(pid);
                _unboundCarded.Remove(pid);
            }

            _snooze.PruneExpired(now, 10000);

            _baselined = true;
            _eventsSeen += arrivals.Count;
        }

        int verdicts = 0;
        foreach (var pid in arrivals)
        {
            if (verdicts >= _options.MaxVerdictsPerSweep)
            {
                lock (_gate)
                {
                    _droppedOverCap += arrivals.Count - verdicts;
                }

                break;
            }

            verdicts++;
            lock (_gate)
            {
                _knownPids[pid] = null;
            }

            VerdictProcess(pid, IsExcluded, now);
        }

        DrainFiles(IsExcluded, now);
        FlushDelta(force: false);
    }

    private void VerdictProcess(int pid, Func<string?, bool> isExcluded, DateTime now)
    {
        // Identity binds per arrival (one handle, one read): the
        // sweep itself is PID-diff only, which is what keeps the 2s
        // cadence inside the ≤2% budget on NEM.
        ProcessIdentity? found;
        try
        {
            found = _identityResolver(pid);
        }
        catch
        {
            found = null;
        }

        if (found is null)
        {
            // Appeared and exited before binding: card the blind
            // spot honestly (per-PID cooldown), or execute-and-exit
            // processes would be invisible by design.
            bool emit;
            lock (_gate)
            {
                emit = _snooze.ShouldEmit("pid:" + pid, "exited", _options.ExeCooldown, now);
                if (!emit)
                {
                    _coalesced++;
                }
            }

            if (emit)
            {
                Publish(new WatchCard(
                    pid, null, "PID " + pid, null,
                    "ExitedBeforeBind", "Appeared and exited before identity could bind.",
                    null, null, WatchSource.Process, now, 0, 0));
            }

            return;
        }

        lock (_gate)
        {
            _knownPids[pid] = found.StartUtc;
        }

        if (string.IsNullOrWhiteSpace(found.ExePath))
        {
            // Pathless (protected/system): one card per PID per
            // cooldown, never per sweep.
            bool emit;
            lock (_gate)
            {
                emit = _snooze.ShouldEmit("pid:" + pid, "nopath", _options.ExeCooldown, now);
                if (!emit)
                {
                    _coalesced++;
                }
            }

            if (emit)
            {
                Publish(new WatchCard(
                    pid, found.StartUtc, found.Name, null,
                    "NoPath", "No executable path visible (system or protected process).",
                    null, null, WatchSource.Process, now,
                    LatencyMs(found.StartUtc, now), 0));
            }

            return;
        }

        string exe = found.ExePath;
        if (isExcluded(exe))
        {
            lock (_gate)
            {
                _excludedSkipped++;
            }

            return;
        }

        string evidence = FileIdentity(exe);
        string key = "exe:" + exe.ToUpperInvariant();
        bool fresh;
        int coalesced;
        lock (_gate)
        {
            fresh = _snooze.ShouldEmit(key, evidence, _options.ExeCooldown, now);
            _coalescedByExe.TryGetValue(key, out coalesced);
            if (fresh)
            {
                _coalescedByExe.Remove(key);
            }
            else
            {
                _coalescedByExe[key] = coalesced + 1;
                _coalesced++;
            }
        }

        if (!fresh)
        {
            return;
        }

        var verdict = PriorityProcessCheck.Check(pid);

        // PID-reuse re-validation: the check above resolves the PID
        // NOW — if the start time moved since binding, the verdict
        // belongs to a different process. Drop it and force
        // re-discovery next sweep (never publish, never queue).
        if (found.StartUtc is not null)
        {
            ProcessIdentity? current = null;
            try
            {
                current = _identityResolver(pid);
            }
            catch
            {
            }

            if (current?.StartUtc is not null && current.StartUtc.Value != found.StartUtc.Value)
            {
                lock (_gate)
                {
                    _knownPids.Remove(pid);
                    // The snooze stamp was consumed for a verdict
                    // that is now dropped: release it so the
                    // re-discovered process can card next sweep.
                    _snooze.Forget(key);
                }

                return;
            }
        }
        else
        {
            // Unbound (resolvable name/path but no start time):
            // one card per PID per session, labelled by PID only.
            lock (_gate)
            {
                if (!_unboundCarded.Add(pid))
                {
                    _coalesced++;
                    return;
                }
            }
        }

        // A NotFound verdict carries no identity ("unknown", no
        // path): fall back to the bound name and exe so the card
        // still says what appeared and exited. Bound verdicts keep
        // their own identity.
        string name = verdict.Name == "unknown" ? found.Name : verdict.Name;
        string? cardExe = verdict.ExePath ?? exe;
        Publish(new WatchCard(
            verdict.Pid, found.StartUtc, name, cardExe,
            verdict.Verdict, verdict.Detail, verdict.Sha256,
            verdict.SignerSubject, WatchSource.Process, now,
            LatencyMs(found.StartUtc, now), coalesced));
        QueueDelta(cardExe);
    }

    private void DrainFiles(Func<string?, bool> isExcluded, DateTime now)
    {
        var seenThisSweep = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (_fileQueue.TryDequeue(out var path))
        {
            if (string.IsNullOrWhiteSpace(path) || !seenThisSweep.Add(path))
            {
                lock (_gate)
                {
                    _coalesced++;
                }

                continue;
            }

            lock (_gate)
            {
                _eventsSeen++;
            }

            if (isExcluded(path))
            {
                lock (_gate)
                {
                    _excludedSkipped++;
                }

                continue;
            }

            string evidence = FileIdentity(path);
            string key = "exe:" + path.ToUpperInvariant();
            bool fresh;
            int coalesced;
            lock (_gate)
            {
                fresh = _snooze.ShouldEmit(key, evidence, _options.ExeCooldown, now);
                _coalescedByExe.TryGetValue(key, out coalesced);
                if (fresh)
                {
                    _coalescedByExe.Remove(key);
                }
                else
                {
                    _coalescedByExe[key] = coalesced + 1;
                    _coalesced++;
                }
            }

            if (!fresh)
            {
                continue;
            }

            var evidenceRecords = StaticEvidenceCollector.CheckFiles([path], maxFiles: 1);
            var file = evidenceRecords.Records.FirstOrDefault();
            if (file is null || !file.Exists)
            {
                Publish(new WatchCard(
                    0, null, Path.GetFileName(path), path, "ExeNotFound",
                    "The file is no longer on disk (" + (file?.Detail ?? "no record") + ").",
                    null, null, WatchSource.File, now, 0, coalesced));
                continue;
            }

            string? company = null;
            try
            {
                company = FileVersionInfo.GetVersionInfo(path).CompanyName;
                if (string.IsNullOrWhiteSpace(company))
                {
                    company = null;
                }
            }
            catch
            {
            }

            if (file.Signed && !string.IsNullOrWhiteSpace(file.SignerSubject))
            {
                Publish(new WatchCard(
                    0, null, Path.GetFileName(path), path, "SignedPublisher",
                    "Authenticode-verified, signed by " + file.SignerSubject + ".",
                    file.Sha256, file.SignerSubject, WatchSource.File, now, 0, coalesced));
            }
            else
            {
                string who = string.IsNullOrWhiteSpace(company) ? "unknown company" : company.Trim();
                Publish(new WatchCard(
                    0, null, Path.GetFileName(path), path, "Unverified",
                    "Not Authenticode-verified (" + who + ") — check first. " +
                        "Unsigned is common and NOT a malware verdict.",
                    file.Sha256, null, WatchSource.File, now, 0, coalesced));
            }

            QueueDelta(path);
        }
    }

    private void QueueDelta(string path)
    {
        lock (_gate)
        {
            if (_delta.Count >= _options.DeltaBatchSize * 4)
            {
                _droppedOverCap++;
                return;
            }

            _delta.Add(path);
        }
    }

    private void FlushDelta(bool force)
    {
        List<string>? batch = null;
        lock (_gate)
        {
            if (_delta.Count == 0)
            {
                return;
            }

            if (!force && DateTime.UtcNow - _lastDeltaUtc < _options.DeltaInterval)
            {
                return;
            }

            batch = _delta
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(_options.DeltaBatchSize)
                .ToList();
            _delta.Clear();
            _lastDeltaUtc = DateTime.UtcNow;
            _deltaPathsQueued += batch.Count;
        }

        if (batch.Count > 0)
        {
            try
            {
                DeltaReady?.Invoke(batch);
            }
            catch
            {
                // A subscriber exception must never kill the sweep.
            }
        }
    }

    private void Publish(WatchCard card)
    {
        lock (_gate)
        {
            _cardsPublished++;
        }

        try
        {
            CardPublished?.Invoke(card);
        }
        catch
        {
            // A subscriber exception must never kill the sweep.
        }
    }

    private static string FileIdentity(string path)
    {
        try
        {
            var info = new FileInfo(path);
            return info.Exists
                ? $"{info.Length}:{info.LastWriteTimeUtc.Ticks}"
                : "missing";
        }
        catch
        {
            return "unstatable";
        }
    }

    private static long LatencyMs(DateTime? startUtc, DateTime observedUtc)
    {
        if (startUtc is null)
        {
            return 0;
        }

        long ms = (long)(observedUtc - startUtc.Value).TotalMilliseconds;
        return ms < 0 ? 0 : ms;
    }
}
