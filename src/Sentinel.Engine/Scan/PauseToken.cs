namespace Sentinel.Engine.Scan;

// Cooperative pause: workers check between files, so pause takes
// effect in well under a second (05 §6). Cancel stays immediate
// via CancellationToken.
public sealed class PauseToken
{
    private volatile bool _paused;

    public bool IsPaused => _paused;

    public void Pause() => _paused = true;

    public void Resume() => _paused = false;

    public async Task WaitIfPausedAsync(CancellationToken ct)
    {
        while (_paused)
        {
            await Task.Delay(50, ct).ConfigureAwait(false);
        }
    }
}
