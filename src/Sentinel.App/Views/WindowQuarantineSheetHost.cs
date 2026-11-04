using System.Windows;
using Sentinel.App.ViewModels;

namespace Sentinel.App.Views;

public sealed class WindowQuarantineSheetHost : IQuarantineSheetHost
{
    public void Show(QuarantineSheetViewModel sheet)
    {
        var window = new QuarantineSheetWindow(sheet)
        {
            Owner = Application.Current?.MainWindow,
        };
        window.ShowDialog();
    }
}
