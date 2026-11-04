namespace Sentinel.App.Services;

// Marshals view-model updates onto the UI thread in the app and
// runs them inline in headless tests. Views never touch the
// Dispatcher directly; view-models never depend on WPF.
public interface IUiDispatcher
{
    void Post(Action action);
}

public sealed class WpfDispatcher : IUiDispatcher
{
    private readonly System.Windows.Threading.Dispatcher _dispatcher;

    public WpfDispatcher(System.Windows.Threading.Dispatcher dispatcher)
    {
        _dispatcher = dispatcher;
    }

    public void Post(Action action)
    {
        if (_dispatcher.CheckAccess())
        {
            action();
        }
        else
        {
            _dispatcher.BeginInvoke(action);
        }
    }
}

public sealed class ImmediateDispatcher : IUiDispatcher
{
    public void Post(Action action) => action();
}
