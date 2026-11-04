using System.Windows;
using Sentinel.App.ViewModels;

namespace Sentinel.App.Views;

// Code-behind for the quarantine-restore sheet: sets the
// ViewModel, closes on request. All behavior lives in
// QuarantineSheetViewModel (headless tested); this file owns
// only the window lifetime.
public partial class QuarantineSheetWindow : Window
{
    public QuarantineSheetWindow(QuarantineSheetViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        viewModel.CloseRequested += Close;
    }
}
