using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows.Input;
using Sentinel.App.Services;
using Sentinel.Engine.Agent;
using Sentinel.Engine.CrashDoctor;
using Sentinel.Store;

namespace Sentinel.App.ViewModels;

// A05: one navigable row of the payload inspector. The summary
// is the list line; Entry carries the detail the inspector shows.
public sealed record PayloadRow(PayloadEntry Entry, string Summary);

// Settings page (02 §16, read-only form): ONLY controls whose
// backend works today. Groups A–F are all present; lines without
// a backend (scheduler, L-permissions, photo egress, vault
// periods, motion, language, PDF) return with their backends —
// absent, never dead. Every control below is wired and tested.
public sealed class SettingsViewModel : ViewModelBase
{
    private readonly SettingsStore _store;
    private readonly Func<SentinelDb> _dbFactory;
    private readonly Func<AgentStore> _agentFactory;
    private readonly Func<string> _dataDir;
    private readonly Func<CloudKeyStore> _keyStore;
    private SentinelSettings _current;

    public SettingsViewModel(
        SettingsStore store,
        Func<SentinelDb> dbFactory,
        Func<AgentStore> agentFactory,
        Func<string>? dataDir = null,
        Func<CloudKeyStore>? keyStoreFactory = null)
    {
        _store = store;
        _dbFactory = dbFactory;
        _agentFactory = agentFactory;
        _dataDir = dataDir ?? (() => SentinelPaths.DataDirectory);
        _keyStore = keyStoreFactory ?? (() => new CloudKeyStore());
        _current = _store.Load();
        NeverTouch = new ObservableCollection<string>(_current.NeverTouch);
        AddNeverCommand = new RelayCommand(_ => AddNever(), _ => !string.IsNullOrWhiteSpace(NewNeverPath));
        RemoveNeverCommand = new RelayCommand(p => RemoveNever(p as string));
        DeleteDataCommand = new RelayCommand(_ => DeleteLocalData());
        OpenDataFolderCommand = new RelayCommand(_ => OpenDataFolder());
        ShowPayloadsCommand = new RelayCommand(_ => ShowPayloads());
        RefreshDataInfo();
    }

    public event EventHandler? AppearanceChanged;

    public event EventHandler? AiToggled;

    public event EventHandler? WatchToggled;

    // E30: live settings for the permission provider. The provider
    // reads through this delegate, so Confirm Sheets always enforce
    // the CURRENT levels, not construction-time copies.
    public SentinelSettings Current => _current;

    public IReadOnlyList<string> ScanModes { get; } = ["Eco", "Balanced"];

    public string DefaultScanMode
    {
        get => _current.DefaultScanMode;
        set { Update(_current with { DefaultScanMode = value }); }
    }

    public int BalancedCapPercent
    {
        get => _current.BalancedCapPercent;
        set { Update(_current with { BalancedCapPercent = value }); }
    }

    public bool PauseOnLowBattery
    {
        get => _current.PauseOnLowBattery;
        set { Update(_current with { PauseOnLowBattery = value }); }
    }

    public bool PriorityWatchEnabled
    {
        get => _current.PriorityWatchEnabled;
        set
        {
            if (_current.PriorityWatchEnabled != value)
            {
                Update(_current with { PriorityWatchEnabled = value });
                WatchToggled?.Invoke(this, EventArgs.Empty);
            }
        }
    }

    public bool AiEnabled
    {
        get => _current.AiEnabled;
        set
        {
            if (_current.AiEnabled != value)
            {
                Update(_current with { AiEnabled = value });
                AiToggled?.Invoke(this, EventArgs.Empty);
            }
        }
    }

    // Live-read from Credential Manager on every get: saved or
    // not, never the value. Refreshed on navigation + after
    // every save/remove (RefreshKeyLine).
    public string CloudKeyLine =>
        _keyStore().HasKey()
            ? "Cloud key: saved — AI runs in the cloud."
            : "Cloud key: not saved — AI runs offline.";

    public string CloudKeyFormatHint =>
        "Paste the Meta Model API key (starts with LLM_). It is stored " +
        "in Windows Credential Manager, never shown again, never logged.";

    // Called on navigation to Settings: re-reads the vault state so
    // a key stored while the app runs shows up without restart.
    public void RefreshKeyLine() => Raise(nameof(CloudKeyLine));

    private string _keyError = string.Empty;

    public string KeyError
    {
        get => _keyError;
        private set => Set(ref _keyError, value);
    }

    // The ONLY key entry point: value comes from the password box,
    // goes straight to the vault, and is never stored, shown, or
    // logged anywhere else. The box is cleared by the caller.
    public void SaveCloudKey(string key)
    {
        KeyError = string.Empty;
        if (string.IsNullOrWhiteSpace(key) || key.Trim().Length < 8)
        {
            KeyError = "That does not look like a key — paste the full value.";
            return;
        }

        try
        {
            _keyStore().SaveKey(key.Trim());
            RefreshKeyLine();
        }
        catch (Exception ex)
        {
            KeyError = "Could not save the key: " + ex.GetType().Name + ".";
        }
    }

    public void RemoveCloudKey()
    {
        KeyError = string.Empty;
        try
        {
            _keyStore().DeleteKey();
            RefreshKeyLine();
        }
        catch (Exception ex)
        {
            KeyError = "Could not remove the key: " + ex.GetType().Name + ".";
        }
    }

    public ObservableCollection<string> NeverTouch { get; }

    private string _newNeverPath = string.Empty;

    public string NewNeverPath
    {
        get => _newNeverPath;
        set
        {
            if (Set(ref _newNeverPath, value))
            {
                ((RelayCommand)AddNeverCommand).RaiseCanExecuteChanged();
            }
        }
    }

    private string _neverError = string.Empty;

    public string NeverError
    {
        get => _neverError;
        private set => Set(ref _neverError, value);
    }

    public ICommand AddNeverCommand { get; }

    public ICommand RemoveNeverCommand { get; }

    public IReadOnlyList<string> Themes { get; } = ["Dark", "Light", "System"];

    public string Theme
    {
        get => _current.Theme;
        set
        {
            if (_current.Theme != value)
            {
                Update(_current with { Theme = value });
                AppearanceChanged?.Invoke(this, EventArgs.Empty);
            }
        }
    }

    public int FontPercent
    {
        get => (int)Math.Round(_current.FontScale * 100);
        set
        {
            int clamped = Math.Clamp(value, 90, 125);
            if (Math.Abs(_current.FontScale - clamped / 100.0) > 0.001)
            {
                Update(_current with { FontScale = clamped / 100.0 });
                AppearanceChanged?.Invoke(this, EventArgs.Empty);
            }
        }
    }

    public bool ReduceMotion
    {
        get => _current.ReduceMotion;
        set
        {
            if (_current.ReduceMotion != value)
            {
                Update(_current with { ReduceMotion = value });
            }
        }
    }

    public bool HighContrast
    {
        get => _current.HighContrast;
        set
        {
            if (_current.HighContrast != value)
            {
                Update(_current with { HighContrast = value });
                AppearanceChanged?.Invoke(this, EventArgs.Empty);
            }
        }
    }

    public string CrashDataPolicy { get; } =
        "Crash data stays on this PC. Dumps and logs are never uploaded in this version.";

    public string TelemetryPolicy { get; } =
        "Off — Sentinel collects no telemetry and has no toggle for it.";

    public string RestorePolicy { get; } =
        "Always on — every future fix creates a restore point first. No switch: safety is not optional.";

    public string DeletionPolicy { get; } =
        "Vault only — nothing is ever permanently deleted by a default flow.";

    public string ModelInfo { get; } = "Spark 1.3 Contributor (cloud)";

    public string PackVersion { get; } = KnowledgePack.PackVersion;

    public string AppVersion { get; } =
        typeof(SettingsViewModel).Assembly.GetName().Version?.ToString() ?? "dev";

    private string _dataInfo = string.Empty;

    public string DataInfo
    {
        get => _dataInfo;
        private set => Set(ref _dataInfo, value);
    }

    private string _payloadPreview = "No AI payloads captured this session yet — run a scan first.";

    public string PayloadPreview
    {
        get => _payloadPreview;
        private set => Set(ref _payloadPreview, value);
    }

    public ICommand DeleteDataCommand { get; }

    public ICommand OpenDataFolderCommand { get; }

    public ICommand ShowPayloadsCommand { get; }

    private string _actionNote = string.Empty;

    public string ActionNote
    {
        get => _actionNote;
        private set => Set(ref _actionNote, value);
    }

    // The session hands its retained payloads here so the inspector
    // shows the exact anonymised JSON of the last AI exchange.
    public Func<IReadOnlyList<string>>? PayloadProvider { get; set; }

    // A05: structured history (entries + eviction accounting) for
    // the navigator. When present it wins over the text fallback.
    public Func<PayloadHistorySnapshot?>? PayloadHistoryProvider { get; set; }

    public ObservableCollection<PayloadRow> PayloadRows { get; } = [];

    private PayloadRow? _selectedPayloadRow;

    public PayloadRow? SelectedPayloadRow
    {
        get => _selectedPayloadRow;
        set
        {
            if (Set(ref _selectedPayloadRow, value))
            {
                PayloadDetail = value is null
                    ? "Select an entry to inspect it."
                    : FormatDetail(value.Entry);
                // The preview mirrors the selected entry, so the
                // last actual request is visible without scrolling.
                PayloadPreview = value is null ? PayloadPreview : PayloadDetail;
            }
        }
    }

    private string _payloadDetail = "Select an entry to inspect it.";

    public string PayloadDetail
    {
        get => _payloadDetail;
        private set => Set(ref _payloadDetail, value);
    }

    private string _payloadCapacityLine = "Nothing captured yet — run a scan first.";

    public string PayloadCapacityLine
    {
        get => _payloadCapacityLine;
        private set => Set(ref _payloadCapacityLine, value);
    }

    private void Update(SentinelSettings next)
    {
        _current = next.Sanitized();
        _store.Save(_current);
        Raise(nameof(DefaultScanMode));
        Raise(nameof(BalancedCapPercent));
        Raise(nameof(PauseOnLowBattery));
        Raise(nameof(PriorityWatchEnabled));
        Raise(nameof(AiEnabled));
        Raise(nameof(Theme));
        Raise(nameof(FontPercent));
    }

    private void AddNever()
    {
        string path = NewNeverPath.Trim();
        if (!Directory.Exists(path))
        {
            NeverError = "That folder does not exist — nothing was added.";
            return;
        }

        if (_current.NeverTouch.Contains(path, StringComparer.OrdinalIgnoreCase))
        {
            NeverError = "Already on the list.";
            return;
        }

        var grown = _current.NeverTouch.Concat([path]).ToList();
        Update(_current with { NeverTouch = grown });
        NeverTouch.Add(path);
        NewNeverPath = string.Empty;
        NeverError = string.Empty;
    }

    private void RemoveNever(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return;
        }

        var shrunk = _current.NeverTouch
            .Where(p => !p.Equals(path, StringComparison.OrdinalIgnoreCase))
            .ToList();
        Update(_current with { NeverTouch = shrunk });
        NeverTouch.Remove(path);
    }

    private void DeleteLocalData()
    {
        try
        {
            using (var db = _dbFactory())
            {
                db.ClearFingerprints();
            }

            ActionNote = "Local scan cache cleared — the next scan re-discovers everything.";
        }
        catch (Exception ex)
        {
            ActionNote = "Could not clear data: " + ex.GetType().Name;
        }

        RefreshDataInfo();
    }

    private void OpenDataFolder()
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = "\"" + _dataDir() + "\"",
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            ActionNote = "Could not open the folder: " + ex.GetType().Name;
        }
    }

    private void ShowPayloads()
    {
        // A05: structured history wins — every retained entry is
        // navigable (including ones past the fifth) and the last
        // actual request is selected by default.
        var snapshot = PayloadHistoryProvider?.Invoke();
        if (snapshot is { Entries.Count: > 0 })
        {
            PayloadRows.Clear();
            foreach (var entry in snapshot.Entries)
            {
                PayloadRows.Add(new PayloadRow(entry, FormatRow(entry)));
            }

            PayloadCapacityLine = FormatCapacity(snapshot);
            SelectedPayloadRow = PayloadRows[^1];
            return;
        }

        // Text fallback (kept for the adopted probe): most recent
        // line wins, never a silent five-line window.
        var lines = PayloadProvider?.Invoke() ?? [];
        PayloadRows.Clear();
        SelectedPayloadRow = null;
        PayloadCapacityLine = lines.Count == 0
            ? "Nothing captured yet — run a scan first."
            : $"{lines.Count} captured (text only) — structured history unavailable.";
        PayloadPreview = lines.Count == 0
            ? "No AI payloads captured this session yet — run a scan first."
            : lines[^1];
        PayloadDetail = PayloadPreview;
    }

    private static string FormatRow(PayloadEntry entry) =>
        $"#{entry.Seq} · {PayloadStages.Label(entry.Kind)} · " +
        $"{HistoryViewModel.FormatBytes(Encoding.UTF8.GetByteCount(entry.Text))}";

    private static string FormatCapacity(PayloadHistorySnapshot snapshot)
    {
        if (snapshot.Evicted <= 0)
        {
            return $"{snapshot.TotalAppended} captured · " +
                $"showing all {snapshot.Entries.Count} (capacity {snapshot.MaxEntries})";
        }

        return $"{snapshot.TotalAppended} captured · " +
            $"showing newest {snapshot.Entries.Count} · " +
            $"{snapshot.Evicted} oldest evicted (capacity {snapshot.MaxEntries})";
    }

    private static string FormatDetail(PayloadEntry entry)
    {
        long bytes = Encoding.UTF8.GetByteCount(entry.Text);
        var head =
            $"#{entry.Seq} · {PayloadStages.Label(entry.Kind)} ({entry.Kind}) · {entry.AtUtc:u}" +
            Environment.NewLine +
            $"To: {entry.Destination} · Class {entry.DataClass} · " +
            $"{bytes} UTF-8 bytes · redacted {(entry.Redacted ? "yes" : "no")} · " +
            $"capture truncated {(entry.Truncated ? "yes" : "no")}" +
            Environment.NewLine + Environment.NewLine;
        const int maxChars = 4000;
        if (entry.Text.Length <= maxChars)
        {
            return head + entry.Text;
        }

        return head + entry.Text[..maxChars] + Environment.NewLine +
            $"…[display truncated: showing first {maxChars} of {entry.Text.Length} chars]";
    }

    public string BuildAuditJson() =>
        new HistoryViewModel(_dbFactory, _agentFactory).BuildAuditJson();

    public string BuildAuditHtml() =>
        new HistoryViewModel(_dbFactory, _agentFactory).BuildAuditHtml();

    private void RefreshDataInfo()
    {
        try
        {
            long bytes = 0;
            foreach (string file in Directory.EnumerateFiles(_dataDir()))
            {
                try
                {
                    bytes += new FileInfo(file).Length;
                }
                catch
                {
                    // One unreadable file never fails the label.
                }
            }

            DataInfo = $"Local data: {bytes / 1024.0:F0} KB in {_dataDir()}";
        }
        catch
        {
            DataInfo = "Local data size unavailable.";
        }
    }
}
