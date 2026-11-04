using Sentinel.Engine.SystemInventory;

namespace Sentinel.Engine.Watch;

// One process-list observation. The production source wraps
// ProcessCollector; tests script snapshots (including reused PIDs,
// exited processes, and protected/pathless rows).
public interface IProcessSnapshotSource
{
    IReadOnlyList<ProcessRecord> Snapshot();
}

public sealed class LiveProcessSnapshotSource : IProcessSnapshotSource
{
    public IReadOnlyList<ProcessRecord> Snapshot()
    {
        try
        {
            // Light rows (pid + name + start): paths resolve per
            // arrival, or the 2s cadence would eat the ≤2% budget.
            return ProcessCollector.CollectLight().Records;
        }
        catch
        {
            // A failed snapshot is a missed sweep, never a crash.
            return [];
        }
    }
}

// One new-or-changed executable observed under a watched folder.
// The production source wraps FileSystemWatchers; tests script events.
public interface IFileEventSource : IDisposable
{
    event Action<string>? FileAppeared;

    // Events the OS dropped (buffer overflow): counted honestly,
    // never silently absorbed.
    event Action? EventsMissed;

    void Start();

    void Stop();
}

public sealed class FolderEventSource : IFileEventSource
{
    private readonly IReadOnlyList<string> _folders;
    private readonly IReadOnlyList<string> _filters;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly object _gate = new();
    private bool _started;
    private bool _disposed;

    public FolderEventSource(IReadOnlyList<string> folders, IReadOnlyList<string> filters)
    {
        _folders = folders;
        _filters = filters;
    }

    public event Action<string>? FileAppeared;

    public event Action? EventsMissed;

    public void Start()
    {
        lock (_gate)
        {
            if (_started || _disposed)
            {
                return;
            }

            _started = true;
            foreach (var folder in _folders)
            {
                foreach (var filter in _filters)
                {
                    try
                    {
                        if (!Directory.Exists(folder))
                        {
                            continue;
                        }

                        var watcher = new FileSystemWatcher(folder, filter)
                        {
                            IncludeSubdirectories = true,
                            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                            EnableRaisingEvents = true,
                        };
                        watcher.Created += OnFile;
                        watcher.Changed += OnFile;
                        watcher.Error += OnError;
                        _watchers.Add(watcher);
                    }
                    catch
                    {
                        // One unwatched folder/filter never stops the rest.
                    }
                }
            }
        }
    }

    public void Stop()
    {
        lock (_gate)
        {
            _started = false;
            foreach (var watcher in _watchers)
            {
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                }
                catch
                {
                }
            }

            _watchers.Clear();
        }
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
    }

    private void OnFile(object sender, FileSystemEventArgs e)
    {
        try
        {
            FileAppeared?.Invoke(e.FullPath);
        }
        catch
        {
            // A subscriber exception must never kill the OS callback.
        }
    }

    private void OnError(object sender, ErrorEventArgs e)
    {
        try
        {
            EventsMissed?.Invoke();
        }
        catch
        {
        }
    }
}
