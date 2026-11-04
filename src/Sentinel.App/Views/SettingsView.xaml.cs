using Microsoft.Win32;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using Sentinel.App.ViewModels;

namespace Sentinel.App.Views;

public partial class SettingsView : UserControl
{
    public SettingsView()
    {
        InitializeComponent();
    }

    private void ExportJson_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is SettingsViewModel vm)
        {
            SaveText("audit-log.json", "JSON audit log (*.json)|*.json", vm.BuildAuditJson());
        }
    }

    private void ExportHtml_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is SettingsViewModel vm)
        {
            SaveText("audit-log.html", "Readable audit log (*.html)|*.html", vm.BuildAuditHtml());
        }
    }

    // PasswordBox never binds (by design): the value moves box →
    // vault → cleared, and is never stored, shown, or logged.
    private void SaveKey_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is SettingsViewModel vm)
        {
            vm.SaveCloudKey(KeyBox.Password);
            KeyBox.Clear();
        }
    }

    private void RemoveKey_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is SettingsViewModel vm)
        {
            vm.RemoveCloudKey();
            KeyBox.Clear();
        }
    }

    private static void SaveText(string fileName, string filter, string content)
    {
        var dialog = new SaveFileDialog { FileName = fileName, Filter = filter };
        if (dialog.ShowDialog() == true)
        {
            File.WriteAllText(dialog.FileName, content);
        }
    }
}
