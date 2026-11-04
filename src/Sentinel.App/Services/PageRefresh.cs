using Sentinel.App.ViewModels;

namespace Sentinel.App.Services;

// A09: the single funnel for background page reads. Collect
// runs off-UI; the continuation (a) records collector faults
// as an observable error instead of crashing on t.Result,
// (b) drops results whose token is stale (rapid navigation /
// refresh / scan replacement), and (c) stamps success. Never
// faults: `done` always runs so buttons re-enable.
public static class PageRefresh
{
    // View-models calling Run without a captured scheduler use
    // this: the UI scheduler on a UI thread, Default elsewhere.
    // FromCurrentSynchronizationContext throws (rather than
    // returning null) when the ambient context is unusable as a
    // scheduler — e.g. under xUnit — so the fallback is guarded.
    public static TaskScheduler CaptureUiOrDefault()
    {
        try
        {
            return TaskScheduler.FromCurrentSynchronizationContext() ?? TaskScheduler.Default;
        }
        catch
        {
            return TaskScheduler.Default;
        }
    }

    public static Task Run<T>(
        RefreshTracker tracker,
        Func<T> collect,
        Action<T> apply,
        string what,
        TaskScheduler ui,
        Action? done = null)
    {
        long token = tracker.Next();
        tracker.MarkBusy(what);
        return Task.Run(collect).ContinueWith(
            t =>
            {
                try
                {
                    if (t.IsFaulted)
                    {
                        Exception cause = t.Exception?.InnerException
                            ?? (Exception?)t.Exception
                            ?? new InvalidOperationException("Collection failed.");
                        tracker.NoteFault(what, cause);
                        return;
                    }

                    if (t.IsCanceled || !tracker.IsCurrent(token))
                    {
                        return;
                    }

                    if (t.Result is null)
                    {
                        return;
                    }

                    try
                    {
                        apply(t.Result);
                    }
                    catch (Exception ex)
                    {
                        tracker.NoteFault(what, ex);
                        return;
                    }

                    tracker.NoteSuccess();
                }
                finally
                {
                    tracker.MarkIdle();
                    done?.Invoke();
                }
            }, ui);
    }
}
