using System.Windows;
using Sentinel.App.ViewModels;

namespace Sentinel.App.Views;

// Production Confirm Sheet host: modal window owned by the main
// window. Passed from MainWindow into MainViewModel so ViewModels
// never reference Views.
public sealed class WindowConfirmSheetHost : IConfirmSheetHost
{
    public void Show(ConfirmSheetViewModel sheet)
    {
        var window = new ConfirmSheetWindow(sheet)
        {
            Owner = Application.Current?.MainWindow,
        };
        window.ShowDialog();
    }
}
