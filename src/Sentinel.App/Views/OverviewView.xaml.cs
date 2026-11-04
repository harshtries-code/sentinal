using System.Windows;
using System.Windows.Controls;
using Sentinel.App.ViewModels;

namespace Sentinel.App.Views;

public partial class OverviewView : UserControl
{
    public OverviewView()
    {
        InitializeComponent();
    }

    // "Review coverage" scrolls the page to the coverage card
    // (BringIntoView works through the window's ScrollViewer).
    private void Coverage_Click(object sender, RoutedEventArgs e)
    {
        CoverageSection.BringIntoView();
    }

    private void Graph_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is OverviewViewModel model)
        {
            model.RelationsGraphView = true;
        }
    }

    private void List_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is OverviewViewModel model)
        {
            model.RelationsGraphView = false;
        }
    }
}
