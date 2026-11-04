using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Sentinel.App.Services;
using Sentinel.App.ViewModels;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.App.Views;

public partial class ThreatsView : UserControl
{
    private ThreatsViewModel? _hooked;

    public ThreatsView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => HookSelection();
    }

    private void HookSelection()
    {
        if (_hooked is not null)
        {
            _hooked.PropertyChanged -= OnModelChanged;
            _hooked = null;
        }

        if (DataContext is ThreatsViewModel model)
        {
            model.PropertyChanged += OnModelChanged;
            _hooked = model;
        }
    }

    private void OnModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ThreatsViewModel.SelectedDetection)
            && sender is ThreatsViewModel model)
        {
            // On-demand local evidence for the selected detection
            // (hash + signature read off-UI; nothing uploaded).
            var row = model.SelectedDetection;
            if (row is null || string.IsNullOrWhiteSpace(row.Path) || row.Path == "—")
            {
                return;
            }

            string path = row.Path;
            long token = model.BeginDetectionEvidence();
            _ = Task.Run(() => StaticEvidenceCollector.CheckFiles([path], 1).Records.FirstOrDefault())
                .ContinueWith(
                    t => model.SetDetectionEvidence(token, t.IsFaulted ? null : t.Result, path),
                    TaskScheduler.FromCurrentSynchronizationContext());
        }

        if (e.PropertyName == nameof(ThreatsViewModel.SelectedProcess)
            && sender is ThreatsViewModel processModel)
        {
            // T51: signer + live connection join for the PID.
            var processRow = processModel.SelectedProcess;
            if (processRow is null || processRow.Id == 0)
            {
                return;
            }

            int pid = processRow.Id;
            string exe = processRow.Path;
            long processToken = processModel.BeginProcessDetail();
            _ = Task.Run(() =>
                {
                    var record = exe == "—" ? null
                        : StaticEvidenceCollector.CheckFiles([exe], 1).Records.FirstOrDefault();
                    var connections = NetworkCollector.Collect().Records
                        .Where(c => c.Pid == pid).ToList();
                    return (record, connections);
                })
                .ContinueWith(
                    t => processModel.SetProcessDetail(
                        processToken, pid,
                        t.IsFaulted ? null : t.Result.record,
                        t.IsFaulted ? [] : t.Result.connections),
                    TaskScheduler.FromCurrentSynchronizationContext());
        }

        if (e.PropertyName == nameof(ThreatsViewModel.SelectedPersistence)
            && sender is ThreatsViewModel persistenceModel)
        {
            // T51: task XML on demand; other rows echo.
            var persistenceRow = persistenceModel.SelectedPersistence;
            if (persistenceRow is null)
            {
                return;
            }

            if (persistenceRow.Type != "Scheduled task")
            {
                persistenceModel.ShowPersistenceSummary(persistenceRow);
                return;
            }

            var rowCopy = persistenceRow;
            long persistenceToken = persistenceModel.BeginPersistenceDetail();
            _ = Task.Run(() => ScheduledTaskCollector.ReadDetail(persistenceRow.Name))
                .ContinueWith(
                    t => persistenceModel.SetPersistenceDetail(
                        persistenceToken, rowCopy,
                        t.IsFaulted ? null : t.Result, null),
                    TaskScheduler.FromCurrentSynchronizationContext());
        }
    }

    private void Refresh_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is ThreatsViewModel model && sender is Button button)
        {
            button.IsEnabled = false;
            var ui = TaskScheduler.FromCurrentSynchronizationContext();
            _ = PageRefresh.Run(
                model.RefreshState,
                ThreatsViewModel.Collect, model.Apply, "threats", ui,
                () => button.IsEnabled = true);
        }
    }

    private void QuickScan_Click(object sender, RoutedEventArgs e)
    {
        PlanDefenderScan(new DefenderScanRequest(DefenderScanKind.Quick, null));
    }

    private void FullScan_Click(object sender, RoutedEventArgs e)
    {
        PlanDefenderScan(new DefenderScanRequest(DefenderScanKind.Full, null));
    }

    private void FolderScan_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog
        {
            Title = "Choose a folder for Defender to scan",
        };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        PlanDefenderScan(
            new DefenderScanRequest(DefenderScanKind.Folder, dialog.FolderName));
    }

    // T50: buttons plan AND open the confirmation sheet (the
    // A03 containment now covers only direct launches — the
    // executor/Confirm path is the lawful way to start a scan).
    // Planning is synchronous and side-effect free, so no
    // background hop is needed.
    private void PlanDefenderScan(DefenderScanRequest request)
    {
        if (DataContext is ThreatsViewModel model)
        {
            model.BeginScan(request);
        }
    }

    private void OfflineScan_Click(object sender, RoutedEventArgs e)
    {
        PlanDefenderScan(new DefenderScanRequest(DefenderScanKind.Offline, null));
    }

    private void Restore_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is ThreatsViewModel model)
        {
            if (model.SelectedQuarantine is { } row)
            {
                model.BeginRestore(row);
            }
            else
            {
                model.NoteQuarantineAction("Select a quarantined item first — nothing was started.");
            }
        }
    }

    private void Keep_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is ThreatsViewModel model)
        {
            if (model.SelectedQuarantine is { } row)
            {
                model.NoteKeep(row);
            }
            else
            {
                model.NoteQuarantineAction("Select a quarantined item first — nothing changed.");
            }
        }
    }

    private void Report_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is ThreatsViewModel model)
        {
            if (model.SelectedQuarantine is { } row)
            {
                model.ReportQuarantine(row);
            }
            else
            {
                model.NoteQuarantineAction("Select a quarantined item first — nothing was opened.");
            }
        }
    }

    private void ChooseFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Choose a file to inspect (local only)",
            CheckFileExists = true,
        };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        CheckFile(dialog.FileName);
    }

    private void CheckFile_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop)
            ? DragDropEffects.Copy
            : DragDropEffects.None;
        e.Handled = true;
    }

    private void CheckFile_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] paths && paths.Length > 0)
        {
            CheckFile(paths[0]);
        }
    }

    private void CheckFile(string path)
    {
        if (DataContext is not ThreatsViewModel model)
        {
            return;
        }

        if (Directory.Exists(path))
        {
            model.SetFileCheck(model.BeginFileCheck(), null, path, "Folders can't be checked — pick a file.");
            return;
        }

        long token = model.BeginFileCheck();
        var ui = TaskScheduler.FromCurrentSynchronizationContext();
        _ = Task.Run(() => StaticEvidenceCollector.CheckFiles([path], 1).Records.FirstOrDefault())
            .ContinueWith(
                t => model.SetFileCheck(token, t.IsFaulted ? null : t.Result, path, null), ui);
    }

    private void ViewPersistence_Click(object sender, RoutedEventArgs e)
    {
        SectionsTab.SelectedIndex = 2;
    }

    private void CopyResource_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is ThreatsViewModel { SelectedDetection: { } row })
        {
            Copy(row.Path);
        }
    }

    private void CopyHash_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is ThreatsViewModel { DetectionEvidence: { } evidence })
        {
            Copy(evidence.HashDisplay);
        }
    }

    private static void Copy(string? text)
    {
        if (string.IsNullOrWhiteSpace(text) || text == "—")
        {
            return;
        }

        try
        {
            Clipboard.SetText(text);
        }
        catch
        {
            // Clipboard busy (RDP/lock) — the text stays visible.
        }
    }
}
