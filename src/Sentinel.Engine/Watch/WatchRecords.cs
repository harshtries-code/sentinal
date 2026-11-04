namespace Sentinel.Engine.Watch;

// Where a watch card came from: a newly observed process, or a
// new/changed executable file seen by the folder lane.
public enum WatchSource
{
    Process,
    File,
}

// One published watch card (P21): a verdict with its observation
// proof. Identity is (Pid, ProcessStartUtc) for processes — a
// reused PID with a new start time is a NEW card, never an update
// to the old one. File cards carry Pid 0.
public sealed record WatchCard(
    int Pid,
    DateTime? ProcessStartUtc,
    string Name,
    string? ExePath,
    string Verdict,
    string Detail,
    string? Sha256,
    string? SignerSubject,
    WatchSource Source,
    DateTime ObservedUtc,
    long LatencyMs,
    int CoalescedCount);

// Rolling watcher statistics for the status line and the P21 perf
// leg. ActiveMs counts stopwatch-measured sweep+verdict work only —
// the honest lower bound of watcher CPU, never a whole-process claim.
public sealed record WatchStats(
    long Sweeps,
    long EventsSeen,
    long CardsPublished,
    long Coalesced,
    long DroppedOverCap,
    long ExcludedSkipped,
    long MissedFolderEvents,
    long DeltaPathsQueued,
    long ActiveMs,
    DateTime LastSweepUtc,
    long LastSweepMs,
    // Cards published this session. The watcher never retracts;
    // the UI owns dismissal, so "live" is as far as the watcher
    // knows — equal to CardsPublished.
    int LiveCards);

// All knobs in one place so tests can shrink time without
// touching production defaults.
public sealed record WatchOptions(
    TimeSpan SweepInterval,
    TimeSpan ExeCooldown,
    int MaxVerdictsPerSweep,
    int DeltaBatchSize,
    TimeSpan DeltaInterval,
    IReadOnlyList<string> WatchFolders,
    IReadOnlyList<string> ExeExtensions)
{
    public static WatchOptions Default(
        IReadOnlyList<string>? watchFolders = null,
        IReadOnlyList<string>? exeExtensions = null)
    {
        return new WatchOptions(
            TimeSpan.FromSeconds(2),
            TimeSpan.FromMinutes(10),
            8,
            20,
            TimeSpan.FromSeconds(30),
            watchFolders ?? DefaultFolders(),
            exeExtensions ?? ["*.exe", "*.dll", "*.msi", "*.ps1", "*.bat", "*.cmd", "*.vbs", "*.js"]);
    }

    public static IReadOnlyList<string> DefaultFolders()
    {
        var folders = new List<string>();
        try
        {
            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            if (!string.IsNullOrWhiteSpace(desktop))
            {
                folders.Add(desktop);
            }

            string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrWhiteSpace(profile))
            {
                folders.Add(Path.Combine(profile, "Downloads"));
            }

            string temp = Path.GetTempPath();
            if (!string.IsNullOrWhiteSpace(temp))
            {
                folders.Add(temp);
            }
        }
        catch
        {
            // A folder that cannot even be named is simply unwatched.
        }

        return folders;
    }
}
