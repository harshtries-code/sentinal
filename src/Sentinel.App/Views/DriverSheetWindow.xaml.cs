using System.Windows;
using Sentinel.App.ViewModels;

namespace Sentinel.App.Views;

// Code-behind for the driver sheet: sets the ViewModel, closes on
// request. All behavior lives in DriverSheetViewModel (headless
// tested); this file owns only the window lifetime.
public partial class DriverSheetWindow : Window
{
    public DriverSheetWindow(DriverSheetViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        viewModel.CloseRequested += Close;
    }
}
