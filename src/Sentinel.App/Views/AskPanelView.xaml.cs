using System.Windows;
using System.Windows.Controls;
using Sentinel.App.ViewModels;
using Sentinel.Engine.Ask;

namespace Sentinel.App.Views;

public partial class AskPanelView : UserControl
{
    public AskPanelView()
    {
        InitializeComponent();
    }

    // Raised when the answer's single action button is pressed. The
    // window executes it through the normal navigation/scan paths.
    public event EventHandler<AskAction>? ActionClicked;

    private void Action_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is AskPanelViewModel vm && vm.Answer?.Action is { } action)
        {
            ActionClicked?.Invoke(this, action);
        }
    }
}
