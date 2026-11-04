using System.Collections.Concurrent;

namespace Sentinel.Engine.Agent;

// In-memory, revision-stamped view of a RUNNING scan. The committed
// SQLite store stays the source of truth for finished generations;
// this hub lets investigation tools see bounded partial evidence
// WITHOUT holding a DB transaction or blocking enumeration.
//
// Every observation bumps the revision. Snapshots are immutable.
// The hub is deliberately dumb: it records what collection reports,
// never interprets it.
public sealed class EvidencePreviewHub
{
    public const int MaxEntries = 100000;

    private readonly ConcurrentDictionary<string, PreviewFileEntry> _files = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DirCounter> _dirs = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentBag<PreviewGap> _gaps = new();
    private int _revision;
    private int _truncated;
    private int _complete;
    private int _aborted;

    public string ScanId { get; } = Guid.NewGuid().ToString("N");

    public int Revision => Volatile.Read(ref _revision);

    public bool IsComplete => Volatile.Read(ref _complete) == 1;

    public bool IsAborted => Volatile.Read(ref _aborted) == 1;

    // Called by scan workers as files are processed. Size/mtime are
    // recorded only when the worker actually observed them; gap-only
    // outcomes still advance the revision (coverage changed).
    public void ObserveFile(string path, long size, long mtimeUtcTicks, string? gapReason)
    {
        if (_files.Count >= MaxEntries && !_files.ContainsKey(path))
        {
            Interlocked.Exchange(ref _truncated, 1);
            Interlocked.Increment(ref _revision);
            return;
        }

        _files[path] = new PreviewFileEntry(path, size, mtimeUtcTicks, gapReason);
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
        {
            _dirs.AddOrUpdate(
                dir,
                _ => new DirCounter { Files = 1, Bytes = size },
                (_, c) => { c.Files++; c.Bytes += size; return c; });
        }

        if (gapReason is not null)
        {
            _gaps.Add(new PreviewGap(path, gapReason));
        }

        Interlocked.Increment(ref _revision);
    }

    public void ObserveGap(string path, string reason)
    {
        _gaps.Add(new PreviewGap(path, reason));
        Interlocked.Increment(ref _revision);
    }

    public void MarkComplete()
    {
        Interlocked.Exchange(ref _complete, 1);
        Interlocked.Increment(ref _revision);
    }

    // Cancelled/failed scans end WITHOUT completing: the preview
    // stays explicitly partial, never a fake "complete" snapshot.
    public void MarkAborted()
    {
        Interlocked.Exchange(ref _aborted, 1);
        Interlocked.Increment(ref _revision);
    }

    public PreviewSnapshot Snapshot()
    {
        var dirs = new List<PreviewDirAggregate>(_dirs.Count);
        foreach (var kv in _dirs)
        {
            dirs.Add(new PreviewDirAggregate(kv.Key, kv.Value.Files, kv.Value.Bytes));
        }

        return new PreviewSnapshot(
            ScanId,
            Revision,
            IsComplete,
            IsAborted,
            Volatile.Read(ref _truncated) == 1,
            _files.Values.ToList(),
            dirs,
            _gaps.ToList());
    }

    private sealed class DirCounter
    {
        public int Files;
        public long Bytes;
    }
}

public sealed record PreviewFileEntry(
    string Path,
    long Size,
    long MTimeUtcTicks,
    string? GapReason);

public sealed record PreviewDirAggregate(
    string Path,
    int Files,
    long Bytes);

public sealed record PreviewGap(string Path, string Reason);

public sealed record PreviewSnapshot(
    string ScanId,
    int Revision,
    bool IsComplete,
    bool IsAborted,
    bool Truncated,
    IReadOnlyList<PreviewFileEntry> Files,
    IReadOnlyList<PreviewDirAggregate> Dirs,
    IReadOnlyList<PreviewGap> Gaps);
