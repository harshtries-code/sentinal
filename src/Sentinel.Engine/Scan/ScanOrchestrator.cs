using System.Collections.Concurrent;
using System.Diagnostics;
using Sentinel.Engine.Agent;
using Sentinel.Engine.Inventory;
using Sentinel.Store;

namespace Sentinel.Engine.Scan;

public sealed record OrchestratedScanResult(
    ScanOutcome Outcome,
    int Generation,
    int FilesSeen,
    long BytesSeen,
    int FilesHashed,
    IReadOnlyList<InventoryGap> Gaps,
    TimeSpan Duration,
    string? RefusalReason,
    string? Error = null);

// Owns scan execution: mode caps, idle gating, priority lanes,
// generations, pause/cancel. Classification lives in Phase 2;
// this class moves bytes and fingerprints, nothing else.
//
// Invariants:
// - One scan per process at a time (single-scan gate): generation
//   reservation is atomic and a bulk transaction is never shared.
// - Producer + workers run concurrently over a BOUNDED queue, so a
//   million-file drive never materializes in memory.
// - Eco admission is checked at start AND continuously: user activity
//   auto-pauses an Eco scan within ~1s, resume is automatic.
// - Every exit path (completed/cancelled/failed/refused) leaves the
//   store consistent and the run status recorded. Refusals consume
//   no generation and write no run row. Aborted runs are recorded
//   OUTSIDE the rolled-back bulk transaction so the row survives.
public sealed class ScanOrchestrator
{
    private static readonly TimeSpan EcoIdleRequired = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan EcoRecheckInterval = TimeSpan.FromMilliseconds(500);
    private static readonly SemaphoreSlim ScanGate = new(1, 1);

    private readonly SentinelDb _db;
    private readonly DiskInventoryScanner _scanner;
    private readonly IIdleProbe _idle;
    private readonly IFullscreenProbe _fullscreen;
    private readonly IBatteryProbe _battery;
    private readonly bool _pauseOnLowBattery;
    private readonly IReadOnlyList<string>? _neverTouch;
    private readonly object _liveGate = new();
    private PriorityWorkQueue<string>? _liveQueue;

    public ScanOrchestrator(
        SentinelDb db,
        IIdleProbe? idle = null,
        IFullscreenProbe? fullscreen = null,
        IBatteryProbe? battery = null,
        bool pauseOnLowBattery = true,
        IReadOnlyList<string>? neverTouch = null)
    {
        _db = db;
        _scanner = new DiskInventoryScanner(db);
        _idle = idle ?? new WindowsIdleProbe();
        _fullscreen = fullscreen ?? new WindowsFullscreenProbe();
        _battery = battery ?? new WindowsBatteryProbe();
        _pauseOnLowBattery = pauseOnLowBattery;
        _neverTouch = neverTouch;
    }

    public async Task<OrchestratedScanResult> RunAsync(
        ScanOptions options,
        PauseToken pause,
        CancellationToken ct = default,
        EvidencePreviewHub? preview = null)
    {
        var refusal = CheckEcoAdmission(options.Mode);
        if (refusal is not null)
        {
            return refusal;
        }

        bool gateTaken = false;
        try
        {
            await ScanGate.WaitAsync(ct).ConfigureAwait(false);
            gateTaken = true;
            FreezeClassifier();
            var census = new Dictionary<string, List<DirListing>>();
            return await ExecuteLockedAsync(
                options,
                string.Join(";", options.Roots),
                (queue, gaps, linkedCt) => ProduceAsync(options, queue, gaps, pause, linkedCt, preview, census),
                pause,
                ct,
                preview,
                census).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!gateTaken)
        {
            // Cancelled before the scan started: no generation, no row.
            return new OrchestratedScanResult(
                ScanOutcome.Cancelled, 0, 0, 0, 0,
                Array.Empty<InventoryGap>(), TimeSpan.Zero, null);
        }
        finally
        {
            if (gateTaken)
            {
                ScanGate.Release();
            }
        }
    }

    // Delta rescan: ONLY the given paths, stamped a new generation.
    // Mid-scan changes never trigger a full rescan (05 §6).
    public async Task<OrchestratedScanResult> RescanPathsAsync(
        IEnumerable<string> paths,
        ScanOptions options,
        PauseToken pause,
        CancellationToken ct = default,
        EvidencePreviewHub? preview = null)
    {
        var refusal = CheckEcoAdmission(options.Mode);
        if (refusal is not null)
        {
            return refusal;
        }

        var wanted = paths.ToList();
        bool gateTaken = false;
        try
        {
            await ScanGate.WaitAsync(ct).ConfigureAwait(false);
            gateTaken = true;
            FreezeClassifier();
            return await ExecuteLockedAsync(
                options,
                "delta",
                (queue, gaps, linkedCt) => ProduceDeltaAsync(wanted, options, queue, gaps, pause, linkedCt),
                pause,
                ct,
                preview).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!gateTaken)
        {
            return new OrchestratedScanResult(
                ScanOutcome.Cancelled, 0, 0, 0, 0,
                Array.Empty<InventoryGap>(), TimeSpan.Zero, null);
        }
        finally
        {
            if (gateTaken)
            {
                ScanGate.Release();
            }
        }
    }

    // P22: freeze scan-time classification inputs for this scan
    // (never-list + clock). Null never-list (tests, legacy callers)
    // leaves tiers to the Collect pass.
    private void FreezeClassifier()
    {
        if (_neverTouch is not null)
        {
            _scanner.Classifier = new Policy.RiskClassifier(_neverTouch.ToArray());
            _scanner.ClassifyUtcNow = DateTime.UtcNow;
        }
    }

    private OrchestratedScanResult? CheckEcoAdmission(ScanMode mode)
    {
        if (mode != ScanMode.Eco)
        {
            return null;
        }

        if (_idle.GetIdleTime() < EcoIdleRequired)
        {
            return Refused(ScanOutcome.RefusedNotIdle, "Eco scans run only after 5 idle minutes.");
        }

        if (_fullscreen.IsForegroundFullscreen())
        {
            return Refused(ScanOutcome.RefusedFullscreen, "Eco scans pause while a fullscreen app runs.");
        }

        // Eco power admission (03 §5, 05 §6): unknown state fails
        // closed (never scan blind), saver or low battery refuses.
        // Balanced/Turbo are explicit user starts and are never
        // refused on power — they pause instead (see continuity).
        var power = _battery.GetPowerState();
        if (!power.Known)
        {
            return Refused(ScanOutcome.RefusedLowPower, "Eco scans wait until the power state is known.");
        }

        if (power.BatterySaverOn)
        {
            return Refused(ScanOutcome.RefusedLowPower, "Eco scans pause while battery saver is on.");
        }

        if (power.IsLowBattery)
        {
            return Refused(ScanOutcome.RefusedLowPower, "Eco scans pause while the battery is low — plug in to scan.");
        }

        return null;
    }

    private async Task<OrchestratedScanResult> ExecuteLockedAsync(
        ScanOptions options,
        string runLabel,
        Func<PriorityWorkQueue<string>, ConcurrentBag<InventoryGap>, CancellationToken, Task> produce,
        PauseToken pause,
        CancellationToken ct,
        EvidencePreviewHub? preview,
        Dictionary<string, List<DirListing>>? census = null)
    {
        var sw = Stopwatch.StartNew();
        int generation;
        long runId;
        try
        {
            _db.BeginBulk();
            generation = _db.GetMaxGeneration() + 1;
            runId = _db.BeginRun(runLabel, generation, options.Mode.ToString());
        }
        catch (Exception ex)
        {
            // The store itself is unusable: nothing started, no row can
            // be recorded (best effort only — the store is the fault).
            sw.Stop();
            try
            {
                _db.EndBulk(commit: false);
                _db.RecordAbortedRun(runLabel, 0, 0, 0, 0,
                    sw.ElapsedMilliseconds, "Failed", ex.GetType().Name,
                    options.Mode.ToString());
            }
            catch
            {
                // The store cannot even record its own failure.
            }

            return new OrchestratedScanResult(
                ScanOutcome.Failed, 0, 0, 0, 0,
                Array.Empty<InventoryGap>(), sw.Elapsed, null, ex.GetType().Name);
        }
        var governor = new CpuGovernor(options.CpuCapPercent);
        using var queue = new PriorityWorkQueue<string>();
        lock (_liveGate)
        {
            // Under the single-scan gate: at most one live queue.
            _liveQueue = queue;
        }

        // 03 §5: the whole process drops to BelowNormal for the
        // locked scan and restores the exact prior level after.
        using var priority = new ScanProcessPriorityScope();
        try
        {
            return await RunLockedCoreAsync(
                options, runLabel, queue, produce, pause, ct, preview,
                generation, runId, governor, sw, census).ConfigureAwait(false);
        }
        finally
        {
            lock (_liveGate)
            {
                if (ReferenceEquals(_liveQueue, queue))
                {
                    _liveQueue = null;
                }
            }
        }
    }

    // Live mid-scan insertion (R5, 04 Phase 2): injects ONE path at
    // priority into the RUNNING scan, any time before it fully
    // drains. False when no scan is active or the scan already
    // drained — call RescanPathsAsync instead. Never throws,
    // never silently drops.
    public bool TryEnqueuePriorityLive(string path)
    {
        lock (_liveGate)
        {
            return _liveQueue?.TryEnqueuePriorityLive(path) ?? false;
        }
    }

    public bool IsScanActive
    {
        get
        {
            lock (_liveGate)
            {
                return _liveQueue is not null;
            }
        }
    }

    private async Task<OrchestratedScanResult> RunLockedCoreAsync(
        ScanOptions options,
        string runLabel,
        PriorityWorkQueue<string> queue,
        Func<PriorityWorkQueue<string>, ConcurrentBag<InventoryGap>, CancellationToken, Task> produce,
        PauseToken pause,
        CancellationToken ct,
        EvidencePreviewHub? preview,
        int generation,
        long runId,
        CpuGovernor governor,
        Stopwatch sw,
        Dictionary<string, List<DirListing>>? census = null)
    {
        var gaps = new ConcurrentBag<InventoryGap>();
        var counts = new ScanCounts();
        bool eco = options.Mode == ScanMode.Eco;

        // Linked token: an internal fault unwinds workers fast without
        // looking like a user cancel (distinguished below via ct).
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        Exception? failure = null;

        var producer = produce(queue, gaps, linked.Token);
        var workers = new Task[options.MaxParallelism];
        for (int i = 0; i < workers.Length; i++)
        {
            workers[i] = WorkerAsync(queue, generation, governor, pause, eco, gaps, counts, linked.Token, preview);
        }

        try
        {
            await producer.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // Internal unwind; outcome decided below.
        }
        catch (OperationCanceledException)
        {
            // User cancel; workers unwind via the same token.
        }
        catch (Exception ex)
        {
            failure ??= ex;
            linked.Cancel();
        }
        finally
        {
            queue.Complete();
        }

        foreach (var worker in workers)
        {
            try
            {
                await worker.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                // Internal unwind after a sibling fault.
            }
            catch (OperationCanceledException)
            {
                // User cancel.
            }
            catch (Exception ex)
            {
                failure ??= ex;
                linked.Cancel();
            }
        }

        sw.Stop();
        if (failure is not null)
        {
            preview?.MarkAborted();
            string error = failure.GetType().Name;
            _db.EndBulk(commit: false);
            _db.RecordAbortedRun(runLabel, generation, counts.FilesSeen, counts.BytesSeen,
                counts.FilesHashed, sw.ElapsedMilliseconds, "Failed", error,
                options.Mode.ToString());
            return new OrchestratedScanResult(
                ScanOutcome.Failed, generation, counts.FilesSeen, counts.BytesSeen,
                counts.FilesHashed, gaps.ToList(), sw.Elapsed, null, error);
        }

        if (ct.IsCancellationRequested)
        {
            preview?.MarkAborted();
            _db.EndBulk(commit: false);
            _db.RecordAbortedRun(runLabel, generation, counts.FilesSeen, counts.BytesSeen,
                counts.FilesHashed, sw.ElapsedMilliseconds, "Cancelled", null,
                options.Mode.ToString());
            return new OrchestratedScanResult(
                ScanOutcome.Cancelled, generation, counts.FilesSeen, counts.BytesSeen,
                counts.FilesHashed, gaps.ToList(), sw.Elapsed, null);
        }

        // P23: completed full runs rewrite the directory census
        // per root, inside the same bulk commit. Deltas never fill
        // the map, so a partial rescan keeps the last full census.
        if (census is not null)
        {
            foreach (var kv in census)
            {
                _db.ReplaceDirStats(
                    kv.Key, DiskInventoryScanner.ToDirStats(kv.Value), generation);
            }
        }

        _db.EndRun(
            runId, counts.FilesSeen, counts.BytesSeen,
            counts.FilesHashed, sw.ElapsedMilliseconds, "Completed", null,
            gaps.Count);
        _db.EndBulk(commit: true);
        preview?.MarkComplete();
        return new OrchestratedScanResult(
            ScanOutcome.Completed, generation, counts.FilesSeen, counts.BytesSeen,
            counts.FilesHashed, gaps.ToList(), sw.Elapsed, null);
    }

    private async Task ProduceAsync(
        ScanOptions options,
        PriorityWorkQueue<string> queue,
        ConcurrentBag<InventoryGap> gaps,
        PauseToken pause,
        CancellationToken ct,
        EvidencePreviewHub? preview,
        Dictionary<string, List<DirListing>>? census = null)
    {
        int sincePauseCheck = 0;
        foreach (var root in options.Roots)
        {
            ct.ThrowIfCancellationRequested();
            var enumGaps = new List<InventoryGap>();
            var listings = new List<DirListing>();
            foreach (var file in FileEnumerator.Enumerate(
                root, enumGaps, ct, options.ExcludedPathPrefixes, listings))
            {
                foreach (var gap in enumGaps)
                {
                    gaps.Add(gap);
                    preview?.ObserveGap(gap.Path, gap.Reason);
                }

                enumGaps.Clear();

                if (++sincePauseCheck >= 64)
                {
                    sincePauseCheck = 0;
                    await pause.WaitIfPausedAsync(ct).ConfigureAwait(false);
                }

                // Cheap stat decides the lane; hashing happens in workers.
                if (IsUnchanged(file))
                {
                    await queue.EnqueueBulkAsync(file, ct).ConfigureAwait(false);
                }
                else
                {
                    await queue.EnqueuePriorityAsync(file, ct).ConfigureAwait(false);
                }
            }

            foreach (var gap in enumGaps)
            {
                gaps.Add(gap);
                preview?.ObserveGap(gap.Path, gap.Reason);
            }

            // P23 census: kept only when the root listing actually
            // ran — a root-level gap keeps the stale census, never
            // blanks it. Delta produce never fills this map.
            if (census is not null
                && !DiskInventoryScanner.HasRootGap(root, enumGaps))
            {
                census[root] = listings;
            }
        }
    }

    private async Task ProduceDeltaAsync(
        List<string> wanted,
        ScanOptions options,
        PriorityWorkQueue<string> queue,
        ConcurrentBag<InventoryGap> gaps,
        PauseToken pause,
        CancellationToken ct)
    {
        foreach (var path in wanted)
        {
            ct.ThrowIfCancellationRequested();
            await pause.WaitIfPausedAsync(ct).ConfigureAwait(false);
            if (IsExcluded(path, options.ExcludedPathPrefixes))
            {
                gaps.Add(new InventoryGap(path, "ExcludedScope"));
                continue;
            }

            await queue.EnqueuePriorityAsync(path, ct).ConfigureAwait(false);
        }
    }

    private async Task WorkerAsync(
        PriorityWorkQueue<string> queue,
        int generation,
        CpuGovernor governor,
        PauseToken pause,
        bool eco,
        ConcurrentBag<InventoryGap> gaps,
        ScanCounts counts,
        CancellationToken ct,
        EvidencePreviewHub? preview)
    {
        while (!queue.IsCompleted)
        {
            ct.ThrowIfCancellationRequested();
            await pause.WaitIfPausedAsync(ct).ConfigureAwait(false);
            if (eco)
            {
                await WaitWhileUserActiveAsync(ct).ConfigureAwait(false);
            }

            await WaitWhilePowerStressedAsync(eco, ct).ConfigureAwait(false);

            if (!queue.TryDequeue(out var file))
            {
                await Task.Delay(10, ct).ConfigureAwait(false);
                continue;
            }

            var outcome = await _scanner.ProcessFileAsync(file, generation, ct, pause).ConfigureAwait(false);
            if (outcome.Gap is not null)
            {
                gaps.Add(outcome.Gap);
            }

            if (outcome.Counted)
            {
                counts.Add(outcome.Size, outcome.Hashed);
                preview?.ObserveFile(file, outcome.Size, outcome.MTimeUtcTicks, outcome.Gap?.Reason);
            }
            else if (outcome.Gap is not null)
            {
                preview?.ObserveGap(file, outcome.Gap.Reason);
            }

            await governor.PaceAsync(ct).ConfigureAwait(false);
        }
    }

    // Eco continuity (05 §6): any user activity pauses within ~1s.
    // Unlike manual pause this is automatic and self-resuming.
    private async Task WaitWhileUserActiveAsync(CancellationToken ct)
    {
        while (_idle.GetIdleTime() < EcoIdleRequired || _fullscreen.IsForegroundFullscreen())
        {
            await Task.Delay(EcoRecheckInterval, ct).ConfigureAwait(false);
        }
    }

    // Power continuity (03 §5, 05 §6): Eco waits out battery saver
    // AND low battery (mandatory); Balanced/Turbo wait out low
    // battery only while the PauseOnLowBattery setting stays on.
    // Automatic and self-resuming, like Eco user-activity waits.
    // The producer is unaffected but the work queue is bounded, so
    // a long wait cannot buffer a drive in RAM.
    private async Task WaitWhilePowerStressedAsync(bool eco, CancellationToken ct)
    {
        while (IsPowerStressed(eco))
        {
            await Task.Delay(EcoRecheckInterval, ct).ConfigureAwait(false);
        }
    }

    private bool IsPowerStressed(bool eco)
    {
        var power = _battery.GetPowerState();
        if (!power.Known)
        {
            return false;
        }

        if (eco && power.BatterySaverOn)
        {
            return true;
        }

        if (!power.IsLowBattery)
        {
            return false;
        }

        return eco || _pauseOnLowBattery;
    }

    private bool IsUnchanged(string file)
    {
        FileInfo info;
        try
        {
            info = new FileInfo(file);
        }
        catch
        {
            return false; // Unknown: priority lane, let processing record the gap.
        }

        long size;
        long mtime;
        try
        {
            size = info.Length;
            mtime = info.LastWriteTimeUtc.Ticks;
        }
        catch
        {
            return false;
        }

        var existing = _db.GetFingerprint(file);
        return existing is not null
            && existing.Size == size
            && existing.MTimeUtcTicks == mtime;
    }

    // A11: the delta/rescan path funnels through the same
    // ScopePaths reading as enumeration and the broker.
    private static bool IsExcluded(string path, IReadOnlyList<string> prefixes)
    {
        if (prefixes.Count == 0)
        {
            return false;
        }

        var canonical = prefixes
            .Select(ScopePaths.CanonicalRoot)
            .Where(x => x is not null)
            .Select(x => x!)
            .ToList();
        return ScopePaths.IsUnderAny(path, canonical);
    }

    private static OrchestratedScanResult Refused(ScanOutcome outcome, string reason)
    {
        return new OrchestratedScanResult(
            outcome, 0, 0, 0, 0, Array.Empty<InventoryGap>(), TimeSpan.Zero, reason);
    }

    private sealed class ScanCounts
    {
        private int _filesSeen;
        private int _filesHashed;
        private long _bytesSeen;

        public int FilesSeen => _filesSeen;

        public int FilesHashed => _filesHashed;

        public long BytesSeen => _bytesSeen;

        public void Add(long size, bool hashed)
        {
            Interlocked.Increment(ref _filesSeen);
            Interlocked.Add(ref _bytesSeen, size);
            if (hashed)
            {
                Interlocked.Increment(ref _filesHashed);
            }
        }
    }
}
