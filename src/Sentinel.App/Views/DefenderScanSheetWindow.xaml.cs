using System.Windows;
using Sentinel.App.ViewModels;

namespace Sentinel.App.Views;

// Code-behind for the Defender scan sheet: sets the ViewModel,
// closes on request. All behavior lives in
// DefenderScanSheetViewModel (headless tested); this file owns
// only the window lifetime.
public partial class DefenderScanSheetWindow : Window
{
    public DefenderScanSheetWindow(DefenderScanSheetViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        viewModel.CloseRequested += Close;
    }
}
