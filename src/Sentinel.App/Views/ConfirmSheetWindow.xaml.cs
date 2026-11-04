using System.Windows;
using Sentinel.App.ViewModels;

namespace Sentinel.App.Views;

// Code-behind for the Confirm Sheet: sets the ViewModel, closes on
// request. All behavior lives in ConfirmSheetViewModel (headless
// tested); this file owns only the window lifetime.
public partial class ConfirmSheetWindow : Window
{
    public ConfirmSheetWindow(ConfirmSheetViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        viewModel.CloseRequested += Close;
    }
}
