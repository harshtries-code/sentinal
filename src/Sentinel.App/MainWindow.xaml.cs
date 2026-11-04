using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using Sentinel.App.Services;
using Sentinel.App.ViewModels;
using Sentinel.App.Views;
using Sentinel.Engine.Scan;
using Sentinel.Store;

namespace Sentinel.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel _model;
    private readonly DispatcherTimer _statusTimer;
    private readonly OverviewView _overviewView;
    private readonly PerformanceView _performanceView;
    private readonly CleanerView _cleanerView;
    private readonly DriversView _driversView;
    private readonly ThreatsView _threatsView;
    private readonly CrashesView _crashesView;
    private readonly HistoryView _historyView;
    private readonly ReportsView _reportsView;
    private readonly SettingsView _settingsView;

    public MainWindow()
    {
        InitializeComponent();
        var dispatcher = new WpfDispatcher(Dispatcher);
        _model = new MainViewModel(
            () => new SentinelDb(SentinelPaths.DatabasePath),
            dispatcher,
            sheetHost: new WindowConfirmSheetHost(),
            viewHistory: () => NavigateToPage(6),
            driverSheetHost: new WindowDriverSheetHost(),
            defenderScanSheetHost: new WindowDefenderScanSheetHost(),
            quarantineSheetHost: new WindowQuarantineSheetHost());
        DataContext = _model;
        _model.Overview.NavigateToPage = NavigateToPage;
        // U21: deep links carry scope — the target page shows which
        // evidence the user came from (Crashes today; the shell
        // routes other pages' scopes as they gain receivers).
        _model.Overview.NavigateWithScope += (page, scope) =>
        {
            NavigateToPage(page);
            if (page == 5 && !string.IsNullOrWhiteSpace(scope))
            {
                _model.Crashes.DeepLinkNote = "From Overview: " + scope.Trim();
            }
        };
        _model.Performance.NavigateToPage = NavigateToPage;
        _model.Crashes.NavigateToPage = NavigateToPage;
        _model.History.NavigateToPage = NavigateToPage;
        _model.Reports.NavigateToPage = NavigateToPage;
        // U27: structured handoff (question + crash highlight key),
        // not a bare string — the Ask panel pre-selects the intent
        // and the crash page highlights the source row on open.
        _model.Crashes.AskAbout = request =>
        {
            _model.Ask.OpenWithQuestion(request.Question, request.IntentHint, request.RowKey);
            if (!string.IsNullOrEmpty(request.RowKey))
            {
                _model.Crashes.HighlightRow(request.RowKey);
            }
        };
        _overviewView = new OverviewView { DataContext = _model.Overview };
        _performanceView = new PerformanceView { DataContext = _model.Performance };
        _cleanerView = new CleanerView { DataContext = _model.Cleaner };
        _driversView = new DriversView { DataContext = _model.Drivers };
        _threatsView = new ThreatsView { DataContext = _model.Threats };
        _crashesView = new CrashesView { DataContext = _model.Crashes };
        _historyView = new HistoryView { DataContext = _model.History };
        _reportsView = new ReportsView { DataContext = _model.Reports };
        _settingsView = new SettingsView { DataContext = _model.Settings };
        PageHost.Content = _overviewView;
        _model.Status.Refresh();
        ApplyAppearance();
        _model.Settings.AppearanceChanged += (_, _) => ApplyAppearance();
        // A09: versioned + fault-guarded like every other
        // collect (a throwing first paint used to crash here).
        Loaded += (_, _) =>
        {
            var ui = TaskScheduler.FromCurrentSynchronizationContext();
            _ = PageRefresh.Run(
                _model.Overview.RefreshState,
                _model.Overview.Collect, _model.Overview.Apply, "overview", ui);
        };

        // A finished scan repopulates the Overview in place: without
        // this the hero keeps showing the pre-scan state until the
        // user navigates away and back. Collection runs off-UI;
        // Apply lands on the captured UI scheduler.
        var uiScheduler = TaskScheduler.FromCurrentSynchronizationContext();
        _model.Session.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ViewModels.ScanSessionViewModel.State)
                && _model.Session.State is ViewModels.ScanSessionState.Completed
                    or ViewModels.ScanSessionState.Cancelled
                    or ViewModels.ScanSessionState.Failed
                    or ViewModels.ScanSessionState.Refused)
            {
                _ = PageRefresh.Run(
                    _model.Overview.RefreshState,
                    _model.Overview.Collect, _model.Overview.Apply, "overview", uiScheduler);
            }
        };

        _statusTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _statusTimer.Tick += (_, _) =>
        {
            _model.Status.Refresh();
            _model.RefreshBanners();
        };
        _statusTimer.Start();

        // P21: the priority watch starts with the window (when
        // enabled) and dies with it — see OnClosed.
        _model.StartWatching();

        AskView.ActionClicked += (_, action) =>
        {
            // U27: answer actions navigate, then highlight — a
            // RowKey only ever selects WITHIN the navigated page.
            if (action.Kind == "OpenPage")
            {
                NavigateToAskPage(action.Target);
                if (action is { RowKey: not null, Target: "Crashes" })
                {
                    _model.Crashes.HighlightRow(action.RowKey);
                }
            }
            else if (action.Kind == "StartBalancedScan")
            {
                _model.Session.Start(ScanMode.Balanced, _model.ScanRoot, _model.Settings.BalancedCapPercent);
            }
        };

        // U27: closing the Ask overlay returns focus to the content
        // (a11y: keyboard users must not lose their place).
        _model.Ask.Closed += () =>
        {
            var focusable = PageHost as FrameworkElement;
            focusable?.MoveFocus(new TraversalRequest(FocusNavigationDirection.First));
        };
    }

    // U27: host-level Ask navigation. Settings routes through the
    // button handler (index 8); null/unknown targets are a no-op.
    private void NavigateToAskPage(string? target)
    {
        if (target is null)
        {
            return;
        }

        var hit = _model.PageNames
            .Select((name, i) => (name, i))
            .FirstOrDefault(x => x.name == target);
        if (hit.name is null)
        {
            return;
        }

        if (hit.i == 8)
        {
            Settings_Click(this, new RoutedEventArgs());
        }
        else
        {
            NavBox.SelectedIndex = hit.i;
        }
    }

    // Settings E: theme + font scale, applied live. The theme is
    // a dictionary swap (Dark/Light share every key); all control
    // brushes are DynamicResource so the swap re-themes at once.
    // Font scale is a true zoom (LayoutTransform) so every explicit
    // FontSize scales too.
    private void ApplyAppearance()
    {
        var merged = Application.Current.Resources.MergedDictionaries;
        string want = ThemeResolver.Resolve(
            _model.Settings.Theme,
            _model.Settings.HighContrast,
            ThemeResolver.ReadAppsUseLightThemeSetting);
        if (merged.Count > 0
            && (merged[0].Source is null
                || !merged[0].Source.OriginalString.Contains(want, StringComparison.OrdinalIgnoreCase)))
        {
            merged[0] = new ResourceDictionary
            {
                Source = new Uri($"Themes/{want}.xaml", UriKind.Relative),
            };
        }

        double scale = _model.Settings.FontPercent / 100.0;
        RootGrid.LayoutTransform = new ScaleTransform(scale, scale);
        // U20: the zoom is the 90–125% text scaler (02 §3), not a
        // reflow substitute (handoff §3 keeps its breakpoints). Past
        // 100% the canvas may exceed the viewport, so allow
        // horizontal scroll ONLY while zoomed instead of clipping;
        // at 100% the no-root-hscroll rule holds.
        CanvasScroll.HorizontalScrollBarVisibility = scale > 1.0
            ? ScrollBarVisibility.Auto
            : ScrollBarVisibility.Disabled;
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        // Caption buttons handle their own clicks; anything else drags.
        DependencyObject? node = e.OriginalSource as DependencyObject;
        while (node is not null)
        {
            if (node is Button)
            {
                return;
            }

            node = VisualTreeHelper.GetParent(node);
        }

        if (e.ClickCount == 2)
        {
            WindowState = WindowState == WindowState.Maximized
                ? WindowState.Normal
                : WindowState.Maximized;
        }
        else
        {
            DragMove();
        }
    }

    private void Ask_Click(object sender, RoutedEventArgs e) => _model.Ask.IsOpen = true;

    private void Min_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void Max_Click(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    // Nav collapse (02 §2): badges-only below 1100px width.
    private void Window_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        bool collapsed = e.NewSize.Width < 1100;
        _model.IsNavCollapsed = collapsed;
        NavPanel.Width = collapsed ? 64 : 208;
    }

    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        NavBox.SelectedIndex = -1;
        SettingsNavButton.SetResourceReference(BackgroundProperty, "AccentSoftBrush");
        ShowPage(8);
    }

    // Overview deep-links: cards, findings, coverage, and activity
    // navigate to real pages (never a dead control). Re-selecting
    // the current page re-collects it (fresh evidence on demand).
    private void NavigateToPage(int index)
    {
        if (index == 8)
        {
            Settings_Click(this, new RoutedEventArgs());
            return;
        }

        if (index is >= 0 and < 8)
        {
            if (NavBox.SelectedIndex == index)
            {
                ShowPage(index);
            }
            else
            {
                NavBox.SelectedIndex = index;
            }
        }
    }

    private void Nav_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (PageHost is null || NavBox.SelectedIndex < 0)
        {
            return;
        }

        SettingsNavButton.ClearValue(BackgroundProperty);
        ShowPage(NavBox.SelectedIndex);
    }

    private void ShowPage(int index)
    {
        var ui = TaskScheduler.FromCurrentSynchronizationContext();
        switch (index)
        {
            case 1:
                PageHost.Content = _performanceView;
                var perfHistory = _model.Status.SampleHistory();
                _ = PageRefresh.Run(
                    _model.Performance.RefreshState,
                    () => _model.Performance.CollectNow(perfHistory),
                    _model.Performance.Apply, "performance", ui);
                break;
            case 2:
                PageHost.Content = _cleanerView;
                _ = PageRefresh.Run(
                    _model.Cleaner.RefreshState,
                    () => CleanerViewModel.Collect(
                        () => new SentinelDb(SentinelPaths.DatabasePath), _model.Settings.NeverTouch),
                    _model.Cleaner.Apply, "storage", ui);
                break;
            case 3:
                PageHost.Content = _driversView;
                _ = PageRefresh.Run(
                    _model.Drivers.RefreshState,
                    DriversViewModel.Collect, _model.Drivers.Apply, "drivers", ui);
                break;
            case 4:
                PageHost.Content = _threatsView;
                _ = PageRefresh.Run(
                    _model.Threats.RefreshState,
                    ThreatsViewModel.Collect, _model.Threats.Apply, "threats", ui);
                break;
            case 5:
                PageHost.Content = _crashesView;
                _ = PageRefresh.Run(
                    _model.Crashes.RefreshState,
                    CrashesViewModel.Collect, _model.Crashes.Apply, "crash history", ui);
                break;
            case 6:
                PageHost.Content = _historyView;
                _ = _model.History.RefreshAsync();
                break;
            case 7:
                PageHost.Content = _reportsView;
                break;
            case 8:
                PageHost.Content = _settingsView;
                _model.Settings.RefreshKeyLine();
                ApplyAppearance(); // Re-resolves "System" against the live OS theme.
                break;
            default:
                PageHost.Content = _overviewView;
                _ = PageRefresh.Run(
                    _model.Overview.RefreshState,
                    _model.Overview.Collect, _model.Overview.Apply, "overview", ui);
                break;
        }
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog
        {
            Title = "Choose a folder to scan (read-only)",
            Multiselect = false,
        };
        if (dialog.ShowDialog(this) == true)
        {
            _model.ScanRoot = dialog.FolderName;
        }
    }

    private void Scan_Click(object sender, RoutedEventArgs e)
    {
        var mode = _model.Settings.DefaultScanMode == "Eco" ? ScanMode.Eco : ScanMode.Balanced;
        _model.Session.Start(mode, _model.ScanRoot, _model.Settings.BalancedCapPercent);
    }

    private void Turbo_Click(object sender, RoutedEventArgs e)
    {
        _model.Session.Start(ScanMode.Turbo, _model.ScanRoot);
    }

    private void Pause_Click(object sender, RoutedEventArgs e) => _model.Session.Pause();

    private void Resume_Click(object sender, RoutedEventArgs e) => _model.Session.Resume();

    private void Cancel_Click(object sender, RoutedEventArgs e) => _model.Session.Cancel();

    protected override void OnClosed(EventArgs e)
    {
        _statusTimer.Stop();
        _model.Shutdown();
        _model.Status.Dispose();
        base.OnClosed(e);
    }
}
