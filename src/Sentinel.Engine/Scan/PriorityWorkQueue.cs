using System.Collections.Concurrent;

namespace Sentinel.Engine.Scan;

// Two-lane living queue: new/changed items outrank the bulk lane.
// Workers always drain priority first, so a threat found mid-scan
// never waits behind 200,000 unchanged files.
// Bounded: producers block instead of buffering a whole drive.
public sealed class PriorityWorkQueue<T> : IDisposable
    where T : notnull
{
    private readonly ConcurrentQueue<T> _priority = new();
    private readonly ConcurrentQueue<T> _bulk = new();
    private readonly SemaphoreSlim _space;
    private readonly object _liveGate = new();
    private int _count;
    private volatile bool _completed;
    private bool _disposed;

    public PriorityWorkQueue(int bound = 4096)
    {
        if (bound < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(bound));
        }

        _space = new SemaphoreSlim(bound, bound);
    }

    public int Count => _count;

    // Locked with live-insertion: the workers' exit decision and
    // the accept/refuse decision are mutually exclusive, which is
    // what makes accepted items unstrandable (see above).
    public bool IsCompleted
    {
        get
        {
            lock (_liveGate)
            {
                return _completed && _count == 0;
            }
        }
    }

    public async Task EnqueuePriorityAsync(T item, CancellationToken ct)
    {
        await _space.WaitAsync(ct).ConfigureAwait(false);
        _priority.Enqueue(item);
        Interlocked.Increment(ref _count);
    }

    public async Task EnqueueBulkAsync(T item, CancellationToken ct)
    {
        await _space.WaitAsync(ct).ConfigureAwait(false);
        _bulk.Enqueue(item);
        Interlocked.Increment(ref _count);
    }

    public bool TryDequeue(out T item)
    {
        if (_priority.TryDequeue(out item!) || _bulk.TryDequeue(out item!))
        {
            Interlocked.Decrement(ref _count);
            _space.Release();
            return true;
        }

        item = default!;
        return false;
    }

    // Live mid-scan insertion (R5): a watcher path injects ONE
    // priority item into a RUNNING scan — including while workers
    // still drain after the producer finished enumerating (the
    // long phase of any big scan). Non-blocking; the accept/refuse
    // decision shares one lock with the workers' exit check, so an
    // accepted item can NEVER strand: workers exit only on
    // (completed AND empty) observed under this lock, and an
    // accepted item keeps the count above zero until some worker
    // dequeues it. Refused only when fully drained (or momentarily
    // full) — the caller falls back to a delta rescan, never a
    // silent drop.
    public bool TryEnqueuePriorityLive(T item)
    {
        lock (_liveGate)
        {
            if (_completed && _count == 0)
            {
                return false;
            }

            if (!_space.Wait(0))
            {
                return false;
            }

            _priority.Enqueue(item);
            Interlocked.Increment(ref _count);
            return true;
        }
    }

    public void Complete()
    {
        lock (_liveGate)
        {
            _completed = true;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _space.Dispose();
    }
}
