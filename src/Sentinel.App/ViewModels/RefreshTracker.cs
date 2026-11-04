namespace Sentinel.App.ViewModels;

// A09: bare version counter for ONE async channel. Pages with
// several independent channels (Threats: page collect +
// selection hash + file check) use one gate each, so a read on
// one channel never invalidates another.
public sealed class AsyncGate
{
    private long _sequence;

    // Takes the newest token, invalidating all older ones.
    public long Next() => Interlocked.Increment(ref _sequence);

    public bool IsCurrent(long token) =>
        Volatile.Read(ref _sequence) == token;
}

// A09: versioned async refresh. Every background page read
// takes a token (Next); only the newest token may Apply, so a
// slow collect finishing after a newer one is dropped instead
// of painting stale rows. Faults are recorded (never thrown
// on the UI thread): last good data stays with its age in the
// error line.
public sealed class RefreshTracker : ViewModelBase
{
    private readonly AsyncGate _gate = new();
    private string? _error;
    private DateTime? _appliedAt;
    private int _busy;
    private string _loadingText = string.Empty;

    // Takes the newest token, invalidating all older ones.
    public long Next() => _gate.Next();

    public bool IsCurrent(long token) => _gate.IsCurrent(token);

    // U20: loading line. Reference-counted so overlapping collects
    // (rapid navigation) never flicker idle between them. Views bind
    // IsRefreshing + LoadingText; blank waits become honest lines.
    public bool IsRefreshing => Volatile.Read(ref _busy) > 0;

    public string LoadingText
    {
        get => _loadingText;
        private set => Set(ref _loadingText, value);
    }

    public void MarkBusy(string what)
    {
        LoadingText = $"Loading {what}…";
        Interlocked.Increment(ref _busy);
        Raise(nameof(IsRefreshing));
    }

    public void MarkIdle()
    {
        if (Interlocked.Decrement(ref _busy) < 0)
        {
            Interlocked.Exchange(ref _busy, 0);
        }

        Raise(nameof(IsRefreshing));
    }

    // Last successful Apply (UTC). Null when nothing ever
    // applied — the error line then says so honestly.
    public DateTime? AppliedAt
    {
        get => _appliedAt;
        private set => Set(ref _appliedAt, value);
    }

    // Null when fresh; set by NoteFault until the next success.
    public string? Error
    {
        get => _error;
        private set => Set(ref _error, value);
    }

    public void NoteSuccess()
    {
        AppliedAt = DateTime.UtcNow;
        Error = null;
    }

    public void NoteFault(string what, Exception ex)
    {
        string cause = ex.GetType().Name;
        Error = AppliedAt is null
            ? $"Couldn't load {what} ({cause}). Nothing to show yet."
            : $"Couldn't refresh {what} ({cause}) — showing data from {AppliedAt:HH:mm} UTC.";
    }
}
