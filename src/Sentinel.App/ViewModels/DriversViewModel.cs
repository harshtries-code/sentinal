using System.Collections.ObjectModel;
using Sentinel.Engine.Actions;
using Sentinel.Engine.Drivers;
using Sentinel.Engine.SystemInventory;
using Sentinel.Store;

namespace Sentinel.App.ViewModels;

public sealed record DriverProblemRow(
    string Device, string Problem, string Code, bool IsPhantom, string DeviceId);

public sealed record DriverRow(string Device, string Version, string Signer, string Status);

public sealed record DeviceDetail(
    string InstanceId, string Version, string Publisher, string Source, string Observed);

public sealed class DeviceRow : ViewModelBase
{
    public DeviceRow(
        string device, string version, string publisher, string status,
        string statusKind, bool isPhantom, DeviceDetail detail)
    {
        Device = device;
        Version = version;
        Publisher = publisher;
        Status = status;
        StatusKind = statusKind;
        IsPhantom = isPhantom;
        Detail = detail;
    }

    public string Device { get; }

    public string Version { get; }

    public string Publisher { get; }

    public string Status { get; }

    // Working | Problem | Phantom — drives row + drawer styling.
    public string StatusKind { get; }

    public bool IsPhantom { get; }

    public DeviceDetail Detail { get; }
}

public sealed record TopologyPartition(string Label, string Sub, bool Unmounted);

public sealed record TopologyDisk(
    string Name, string Sub, IReadOnlyList<TopologyPartition> Partitions,
    string StatusLine, bool HasIssue);

// Drivers page (02 §8, boards 04 + 22): live Device Manager
// state plus the signed-driver inventory, merged into one table,
// plus disk topology cards — and, since D43, lawful update/rollback
// actions behind the driver ladder (searched read-only, confirmed
// in the driver sheet, executed through the action choke point).
// With null action services the page stays honestly read-only.
public sealed class DriversViewModel : ViewModelBase
{
    // A09: versions navigation/refresh collects; faults surface
    // here with the last table kept.
    public RefreshTracker RefreshState { get; } = new();

    private readonly Func<PassportDb>? _passportFactory;
    private readonly DriverActionServices? _actions;

    // P26: set when device-history persistence fails (page data is
    // unaffected); null after a successful persist or when no
    // factory is wired.
    public string? LastPersistError { get; private set; }

    // P26: passportFactory persists device history for trends.
    // Null (tests, transient views) collects without persisting.
    // D43: actions wires update/rollback; null stays read-only.
    public DriversViewModel(
        Func<PassportDb>? passportFactory = null,
        DriverActionServices? actions = null)
    {
        _passportFactory = passportFactory;
        _actions = actions;
    }

    public ObservableCollection<DriverProblemRow> Problems { get; } = [];

    public ObservableCollection<DriverRow> Drivers { get; } = [];

    public ObservableCollection<DeviceRow> Devices { get; } = [];

    public ObservableCollection<TopologyDisk> Topology { get; } = [];

    private string _summary = "Not inspected yet.";

    public string Summary
    {
        get => _summary;
        private set => Set(ref _summary, value);
    }

    private string _coverage = string.Empty;

    public string Coverage
    {
        get => _coverage;
        private set => Set(ref _coverage, value);
    }

    // P28: the device-diagnostics boundary, printed verbatim from
    // the Engine matrix (never hand-copied, so page and matrix
    // cannot disagree).
    public string Boundaries => DeviceCapabilityMatrix.BoundariesLine;

    private string _machineLine = string.Empty;

    public string MachineLine
    {
        get => _machineLine;
        private set => Set(ref _machineLine, value);
    }

    private string _liveLine = "Live inventory";

    public string LiveLine
    {
        get => _liveLine;
        private set => Set(ref _liveLine, value);
    }

    private string _driverCountLine = string.Empty;

    public string DriverCountLine
    {
        get => _driverCountLine;
        private set => Set(ref _driverCountLine, value);
    }

    private string _chkdskLine = string.Empty;

    public string ChkdskLine
    {
        get => _chkdskLine;
        private set => Set(ref _chkdskLine, value);
    }

    private string _chipAll = "All";

    public string ChipAll
    {
        get => _chipAll;
        private set => Set(ref _chipAll, value);
    }

    private string _chipProblems = "Problems";

    public string ChipProblems
    {
        get => _chipProblems;
        private set => Set(ref _chipProblems, value);
    }

    private bool _problemsOnly;

    public bool ProblemsOnly
    {
        get => _problemsOnly;
        set
        {
            if (Set(ref _problemsOnly, value))
            {
                RefillDevices();
            }
        }
    }

    private DeviceRow? _selectedDevice;

    public DeviceRow? SelectedDevice
    {
        get => _selectedDevice;
        set
        {
            if (Set(ref _selectedDevice, value))
            {
                // A new device invalidates the last check.
                ClearCheckState();
                Raise(nameof(CanCheckUpdates));
                Raise(nameof(CanCheckRollback));
                Raise(nameof(ActionsAvailable));
            }
        }
    }

    private bool _hasProblems;

    public bool HasProblems
    {
        get => _hasProblems;
        private set => Set(ref _hasProblems, value);
    }

    private DriversSnapshot? _snapshot;

    private bool _showDisconnected = true;

    // Code 45 = not currently attached (M3 SetupAPI note). Shown by
    // default so nothing hides; the checkbox filters them out.
    public bool ShowDisconnected
    {
        get => _showDisconnected;
        set
        {
            if (Set(ref _showDisconnected, value))
            {
                RefillDevices();
                if (_snapshot is not null)
                {
                    FillProblems(_snapshot);
                }
            }
        }
    }

    public void Refresh() => Apply(Collect());

    public static DriversSnapshot Collect()
    {
        var problems = DriverCollector.CollectDeviceProblems();
        var drivers = DriverCollector.Collect();
        var topology = DiskTopologyCollector.Collect();
        var chkdsk = EventCollector.CollectChkdskHistory(
            DateTime.UtcNow.AddDays(-90), 50);

        var problemRows = problems.Records
            .OrderBy(r => r.ErrorCode)
            .Select(r => new DriverProblemRow(
                string.IsNullOrWhiteSpace(r.Name) ? r.DeviceId : r.Name,
                r.ErrorName,
                "Code " + r.ErrorCode,
                r.ErrorCode == 45,
                r.DeviceId))
            .ToList();
        var driverRows = drivers.Records
            .OrderBy(r => r.DeviceName)
            .Select(r => new DriverRow(
                r.DeviceName,
                r.DriverVersion ?? "—",
                r.Signer ?? "—",
                r.Status ?? "—"))
            .ToList();
        var topologyCards = topology.Status == CollectionStatus.Success
            ? topology.Records.Select(BuildTopologyDisk).ToList()
            : [];

        var coverage = new List<string>();
        if (problems.Status != CollectionStatus.Success)
        {
            coverage.Add($"Device problems: {problems.Status}.");
        }

        if (drivers.Status != CollectionStatus.Success)
        {
            coverage.Add($"Driver inventory: {drivers.Status}.");
        }

        if (topology.Status != CollectionStatus.Success)
        {
            coverage.Add($"Disk topology: {topology.Status}.");
        }

        if (chkdsk.Status == CollectionStatus.Failed)
        {
            coverage.Add("Filesystem check history unreadable.");
        }

        return new DriversSnapshot(
            problems.Records.Count == 0
                ? "No device problems reported by Device Manager."
                : $"{CountText.Of(problems.Records.Count, "device problem")} reported by Device Manager.",
            coverage.Count == 0 ? "All sources inspected." : "Coverage: " + string.Join(" ", coverage),
            problemRows, driverRows, topologyCards, DateTime.UtcNow,
            BuildChkdskLine(chkdsk));
    }

    // P24 (R06.2/R06.3): the filesystem-check story in one line.
    // Absence of reports is stated as absence — never as health.
    public static string BuildChkdskLine(CollectionResult<TargetedEventRecord> chkdsk)
    {
        if (chkdsk.Status == CollectionStatus.Failed)
        {
            return "Filesystem check history could not be read — see Coverage.";
        }

        if (chkdsk.Records.Count == 0)
        {
            return "No filesystem check reports in the last 90 days — absence, not health.";
        }

        var newest = chkdsk.Records
            .OrderByDescending(r => r.TimeUtc)
            .First();
        string outcome = "completed with findings — read the report in Event Viewer";
        if (newest.Message.Contains("no problems", StringComparison.OrdinalIgnoreCase))
        {
            outcome = "no problems found";
        }
        else if (newest.Message.Contains("insufficient disk space", StringComparison.OrdinalIgnoreCase))
        {
            outcome = "could not complete (disk space)";
        }

        string count = chkdsk.Records.Count == 1
            ? "1 report in 90 days"
            : $"{chkdsk.Records.Count} reports in 90 days";
        return $"Last filesystem check {newest.TimeUtc.ToLocalTime():g} " +
            $"({newest.Provider} event {newest.Id}): {outcome} · {count}.";
    }

    public static TopologyDisk BuildTopologyDisk(DiskTopologyRecord disk)
    {
        var partitions = new List<TopologyPartition>();
        foreach (var part in disk.Partitions)
        {
            if (part.Volume is { } vol)
            {
                string label = !string.IsNullOrWhiteSpace(vol.DriveLetter)
                    ? $"{vol.DriveLetter}: {(string.IsNullOrWhiteSpace(vol.Label) ? "Volume" : vol.Label)}"
                    : (string.IsNullOrWhiteSpace(vol.Label) ? "Volume" : vol.Label);
                partitions.Add(new TopologyPartition(
                    label,
                    $"{FormatBytes(vol.SizeBytes)} {(vol.FileSystem ?? "Unknown")}".Trim(),
                    false));
            }
            else
            {
                bool unmounted = string.IsNullOrWhiteSpace(part.DriveLetter);
                partitions.Add(new TopologyPartition(
                    string.IsNullOrWhiteSpace(part.Type) ? "Partition" : part.Type,
                    unmounted
                        ? FormatBytes(part.SizeBytes) + " · not mounted"
                        : FormatBytes(part.SizeBytes),
                    unmounted));
            }
        }

        int unmountedCount = partitions.Count(p => p.Unmounted);
        string status = unmountedCount == 0
            ? $"{partitions.Count} partitions · No issues detected"
            : $"{CountText.Of(partitions.Count, "partition")} · {CountText.Of(unmountedCount, "volume")} not mounted";
        // P24 (R06.6): the PnP device identity joins the topology
        // disk to the device table; unresolved stays stated.
        string device = string.IsNullOrWhiteSpace(disk.PnpDeviceId)
            ? "device ID unresolved"
            : disk.PnpDeviceId;
        return new TopologyDisk(
            $"Disk {disk.DiskNumber}",
            $"{disk.Name} · {FormatBytes(disk.SizeBytes)} · {disk.PartitionStyle} · {device}",
            partitions, status, unmountedCount > 0);
    }

    // Merge: problem rows first (enriched from the driver table on
    // exact name match), then unmatched drivers. No fuzzy merge —
    // a missed match shows two honest rows, never a wrong join.
    public static IReadOnlyList<DeviceRow> BuildDevices(
        IReadOnlyList<DriverProblemRow> problems,
        IReadOnlyList<DriverRow> drivers,
        string observed)
    {
        var byName = new Dictionary<string, DriverRow>(StringComparer.OrdinalIgnoreCase);
        foreach (var driver in drivers)
        {
            byName.TryAdd(driver.Device, driver);
        }

        var rows = new List<DeviceRow>();
        var matched = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var problem in problems)
        {
            byName.TryGetValue(problem.Device, out var driver);
            if (driver is not null)
            {
                matched.Add(driver.Device);
            }

            string kind = problem.IsPhantom ? "Phantom" : "Problem";
            rows.Add(new DeviceRow(
                problem.Device,
                driver?.Version ?? "—",
                driver?.Signer ?? "—",
                problem.IsPhantom ? $"Not connected ({problem.Code})" : problem.Code,
                kind, problem.IsPhantom,
                new DeviceDetail(
                    problem.DeviceId,
                    driver?.Version ?? "Unavailable",
                    driver?.Signer ?? "—",
                    "Windows device state", observed)));
        }

        foreach (var driver in drivers)
        {
            if (matched.Contains(driver.Device))
            {
                continue;
            }

            // Absence of "OK" is not a fault: Win32_PnPSignedDriver.Status is
            // routinely empty, and Device Manager is the authoritative problem
            // source (merged in the problem loop above). Only clear fault
            // values mark a non-listed driver as a problem.
            bool fault = IsFaultStatus(driver.Status);
            string display = string.Equals(driver.Status, "OK", StringComparison.OrdinalIgnoreCase)
                ? "Working"
                : driver.Status;
            rows.Add(new DeviceRow(
                driver.Device, driver.Version, driver.Signer,
                display,
                fault ? "Problem" : "Working", false,
                new DeviceDetail(
                    driver.Device, driver.Version, driver.Signer,
                    "Driver inventory", observed)));
        }

        return rows;
    }

    private static bool IsFaultStatus(string status) =>
        string.Equals(status, "Error", StringComparison.OrdinalIgnoreCase)
        || string.Equals(status, "Degraded", StringComparison.OrdinalIgnoreCase)
        || string.Equals(status, "Pred Fail", StringComparison.OrdinalIgnoreCase)
        || string.Equals(status, "NonRecover", StringComparison.OrdinalIgnoreCase)
        || string.Equals(status, "Failed", StringComparison.OrdinalIgnoreCase);

    public void Apply(DriversSnapshot s)
    {
        Summary = s.Summary;
        Coverage = s.Coverage;
        MachineLine = BuildMachineLine();
        ChkdskLine = s.ChkdskLine;
        LiveLine = "Live inventory · updated " + s.CollectedUtc.ToLocalTime().ToString("HH:mm:ss");
        DriverCountLine = s.Drivers.Count == 0
            ? "No driver records"
            : $"{s.Drivers.Count} driver records";
        _snapshot = s;
        FillProblems(s);

        Drivers.Clear();
        foreach (var row in s.Drivers)
        {
            Drivers.Add(row);
        }

        Topology.Clear();
        foreach (var disk in s.Topology)
        {
            Topology.Add(disk);
        }

        HasProblems = s.Problems.Count > 0;
        SelectedDevice = null;
        RefillDevices();
        RefreshState.NoteSuccess();
        PersistDeviceStates(s);
    }

    // P26: every applied collect appends device state to the
    // Passport (append-on-change inside the store: an unchanged
    // fleet costs zero rows). Devices known-but-now-healthy are
    // recorded recovered, so a healed problem never reads stale.
    private void PersistDeviceStates(DriversSnapshot s)
    {
        if (_passportFactory is null)
        {
            return;
        }

        try
        {
            using var passport = _passportFactory();
            var driversByName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var driver in s.Drivers)
            {
                driversByName.TryAdd(driver.Device, driver.Version);
            }

            var rows = new List<(string InstanceId, string Name, int Problem, string Status, string? DriverVersion)>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var problem in s.Problems)
            {
                seen.Add(problem.DeviceId);
                driversByName.TryGetValue(problem.Device, out string? version);
                rows.Add((
                    problem.DeviceId,
                    problem.Device,
                    ParseProblemCode(problem.Code),
                    problem.Problem,
                    version == "—" ? null : version));
            }

            foreach (var known in passport.QueryDeviceLatest())
            {
                if (!seen.Contains(known.InstanceId) && known.Problem != 0)
                {
                    rows.Add((known.InstanceId, known.Name, 0, "Working", known.DriverVersion));
                }
            }

            passport.RecordDeviceStates(rows);
            LastPersistError = null;
        }
        catch (Exception ex)
        {
            // Persistence must never break the page; the failure
            // stays observable here instead of vanishing.
            LastPersistError = ex.GetType().Name;
        }
    }

    // Problem codes render as "Code N" (see Collect); unparseable
    // codes keep -1 while the Status text carries the truth.
    public static int ParseProblemCode(string code)
    {
        string digits = code.StartsWith("Code ", StringComparison.Ordinal)
            ? code.Substring(5).Trim()
            : code.Trim();
        return int.TryParse(digits, out int parsed) ? parsed : -1;
    }

    private void RefillDevices()
    {
        Devices.Clear();
        if (_snapshot is null)
        {
            ChipAll = "All";
            ChipProblems = "Problems";
            return;
        }

        string observed = "Today, " + _snapshot.CollectedUtc.ToLocalTime().ToString("HH:mm");
        var all = BuildDevices(_snapshot.Problems, _snapshot.Drivers, observed);
        int problemCount = all.Count(r => r.StatusKind != "Working");
        ChipAll = $"All ({all.Count})";
        ChipProblems = $"Problems ({problemCount})";
        foreach (var row in all)
        {
            if (row.IsPhantom && !_showDisconnected)
            {
                continue;
            }

            if (_problemsOnly && row.StatusKind == "Working")
            {
                continue;
            }

            Devices.Add(row);
        }
    }

    private void FillProblems(DriversSnapshot s)
    {
        Problems.Clear();
        foreach (var row in s.Problems)
        {
            if (!row.IsPhantom || _showDisconnected)
            {
                Problems.Add(row);
            }
        }
    }

    internal static string BuildMachineLine()
    {
        try
        {
            return $"{Environment.MachineName} · {Environment.OSVersion.VersionString}";
        }
        catch
        {
            return "This PC";
        }
    }

    internal static string FormatBytes(long? bytes)
    {
        if (bytes is null or <= 0)
        {
            return "size unknown";
        }

        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = bytes.Value;
        int unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return $"{value:0.#} {units[unit]}";
    }

    // ---- D43: update/rollback checks + sheets ----

    private DriverPreview? _updatePreview;
    private DriverRollbackPreview? _rollbackPreview;
    private CancellationTokenSource? _checkCts;

    public ObservableCollection<DriverPreviewItem> UpdateCandidates { get; } = [];

    public ObservableCollection<DriverUnsupportedDevice> UpdateUnsupported { get; } = [];

    public ObservableCollection<DriverRollbackItem> RollbackCandidates { get; } = [];

    public ObservableCollection<DriverUnsupportedDevice> RollbackUnsupported { get; } = [];

    public bool ActionsAvailable => _actions is not null;

    private string _updateStateLine = "Select a device, then check for updates.";

    public string UpdateStateLine
    {
        get => _updateStateLine;
        private set => Set(ref _updateStateLine, value);
    }

    private string? _oemSetLine;

    public string? OemSetLine
    {
        get => _oemSetLine;
        private set => Set(ref _oemSetLine, value);
    }

    private string _rollbackStateLine = "Select a device, then check for a rollback target.";

    public string RollbackStateLine
    {
        get => _rollbackStateLine;
        private set => Set(ref _rollbackStateLine, value);
    }

    private bool _isChecking;

    public bool IsChecking
    {
        get => _isChecking;
        private set
        {
            if (Set(ref _isChecking, value))
            {
                Raise(nameof(CanCheckUpdates));
                Raise(nameof(CanCheckRollback));
            }
        }
    }

    public bool CanCheckUpdates =>
        _actions is not null && SelectedDevice is not null && !IsChecking;

    public bool CanCheckRollback =>
        _actions is not null && SelectedDevice is not null &&
        _passportFactory is not null && !IsChecking;

    public bool CanOpenUpdateSheet =>
        _updatePreview is not null && _updatePreview.RefusedReason is null &&
        (_updatePreview.Included.Count > 0 || _updatePreview.OemSet is not null) &&
        !IsChecking;

    public bool CanOpenRollbackSheet =>
        _rollbackPreview is not null && _rollbackPreview.RefusedReason is null &&
        _rollbackPreview.Included.Count > 0 && !IsChecking;

    private void ClearCheckState()
    {
        _updatePreview = null;
        _rollbackPreview = null;
        UpdateCandidates.Clear();
        UpdateUnsupported.Clear();
        RollbackCandidates.Clear();
        RollbackUnsupported.Clear();
        OemSetLine = null;
        _updateStateLine = "Select a device, then check for updates.";
        _rollbackStateLine = "Select a device, then check for a rollback target.";
        Raise(nameof(UpdateStateLine));
        Raise(nameof(RollbackStateLine));
        Raise(nameof(CanOpenUpdateSheet));
        Raise(nameof(CanOpenRollbackSheet));
    }

    // Code-behind entry point (mirrors the Cleaner's BeginVaultAction
    // shape): starts the read-only check, guarded against reentry.
    public void CheckUpdates()
    {
        if (IsChecking)
        {
            return;
        }

        _checkCts?.Cancel();
        _checkCts = new CancellationTokenSource();
        _ = CheckUpdatesAsync(_checkCts.Token);
    }

    public void CancelCheck() => _checkCts?.Cancel();

    // Test seam: the same path, awaitable.
    public async Task CheckUpdatesAsync(CancellationToken ct)
    {
        var device = SelectedDevice;
        if (_actions is null)
        {
            UpdateStateLine = "Driver actions aren't wired in this build — this page stays read-only.";
            return;
        }

        if (device is null)
        {
            UpdateStateLine = "Select a device first.";
            return;
        }

        IsChecking = true;
        UpdateCandidates.Clear();
        UpdateUnsupported.Clear();
        OemSetLine = null;
        UpdateStateLine = $"Checking Windows Update for {device.Device}… (read-only search)";

        try
        {
            var ops = _actions.Ops();
            string instanceId = device.Detail.InstanceId;
            string? publisher = device.Publisher == "—" ? null : device.Publisher;
            var ladder = DriverSourceLadder.Resolve(publisher, OemDetector.Detect());
            bool wantOem = ladder.Steps.Any(s => s.Source == DriverSource.OemCatalogue);

            // Live reads off the UI thread: a WU search can take
            // minutes. All read-only — safe on any machine.
            var live = await Task.Run(() => ops.ReadDevice(instanceId), ct);
            var candidates = await Task.Run(
                () => ops.SearchWindowsUpdate(instanceId, live.Name ?? device.Device, live.HardwareIds), ct);
            OemScanSet? scan = wantOem
                ? await Task.Run(() => ops.ScanOemCatalogue(), ct)
                : null;

            var preview = DriverPreviewBuilder.Build(
                [new DriverPreviewDevice(
                    instanceId, device.Device, live.DriverVersion, live.DriverDate,
                    live.HardwareIds, ladder, candidates)],
                scan,
                _actions.Blocklist().Keys,
                ElevationPolicy.IsProcessElevated());
            _updatePreview = preview;

            foreach (var item in preview.Included)
            {
                UpdateCandidates.Add(item);
            }

            foreach (var unsupported in preview.Unsupported)
            {
                UpdateUnsupported.Add(unsupported);
            }

            if (preview.OemSet is not null)
            {
                OemSetLine = $"{preview.OemSet.VendorName} catalogue set: " +
                    $"{preview.OemSet.Titles.Count} update(s) — confirmed as one set. " +
                    preview.OemSet.Summary;
            }
            else if (preview.OemNote is not null)
            {
                OemSetLine = preview.OemNote;
            }

            UpdateStateLine = preview.RefusedReason
                ?? (preview.Included.Count > 0 || preview.OemSet is not null
                    ? $"{UpdateCandidates.Count + (preview.OemSet is null ? 0 : 1)} update(s) found — review and confirm."
                    : "No updates for this device — reasons below.");
        }
        catch (OperationCanceledException)
        {
            UpdateStateLine = "Check cancelled — nothing was searched.";
        }
        catch (Exception ex)
        {
            UpdateStateLine = $"The update check failed ({ex.GetType().Name}): {ex.Message}";
        }
        finally
        {
            IsChecking = false;
            Raise(nameof(CanOpenUpdateSheet));
        }
    }

    public void OpenUpdateSheet()
    {
        if (_actions is null)
        {
            UpdateStateLine = "Driver actions aren't wired in this build — this page stays read-only.";
            return;
        }

        if (_updatePreview is null)
        {
            UpdateStateLine = "Check for updates first.";
            return;
        }

        var template = ActionRegistry.Find("driver_update_from_ladder");
        if (template is null || template.Status != TemplateStatus.Active)
        {
            UpdateStateLine = "Driver updates are unavailable in this build — the preview stays informational.";
            return;
        }

        var sheet = new DriverSheetViewModel(_updatePreview, template, _actions.Dispatcher)
        {
            ViewHistory = _actions.ViewHistory,
        };
        _actions.Host.Show(sheet);
    }

    public void CheckRollback()
    {
        if (IsChecking)
        {
            return;
        }

        _checkCts?.Cancel();
        _checkCts = new CancellationTokenSource();
        _ = CheckRollbackAsync(_checkCts.Token);
    }

    public async Task CheckRollbackAsync(CancellationToken ct)
    {
        var device = SelectedDevice;
        if (_actions is null)
        {
            RollbackStateLine = "Driver actions aren't wired in this build — this page stays read-only.";
            return;
        }

        if (device is null)
        {
            RollbackStateLine = "Select a device first.";
            return;
        }

        if (_passportFactory is null)
        {
            RollbackStateLine = "Device history is unavailable — rollback needs an on-record earlier version.";
            return;
        }

        IsChecking = true;
        RollbackCandidates.Clear();
        RollbackUnsupported.Clear();
        RollbackStateLine = $"Looking for a rollback target for {device.Device}… (read-only)";

        try
        {
            var ops = _actions.Ops();
            string instanceId = device.Detail.InstanceId;
            var live = await Task.Run(() => ops.ReadDevice(instanceId), ct);
            var store = await Task.Run(() => ops.EnumStore(), ct);

            IReadOnlyList<DeviceHistoryRow> History(string id)
            {
                using var passport = _passportFactory();
                return passport.QueryDeviceHistory(id);
            }

            var preview = DriverPreviewBuilder.BuildRollback(
                [new DriverRollbackRequest(
                    instanceId, device.Device, live.HardwareIds.FirstOrDefault(), live.DriverVersion)],
                History,
                store,
                ElevationPolicy.IsProcessElevated());
            _rollbackPreview = preview;

            foreach (var item in preview.Included)
            {
                RollbackCandidates.Add(item);
            }

            foreach (var unsupported in preview.Unsupported)
            {
                RollbackUnsupported.Add(unsupported);
            }

            RollbackStateLine = preview.RefusedReason
                ?? (preview.Included.Count > 0
                    ? "A rollback target was found — review and confirm."
                    : "No rollback target for this device — reasons below.");
        }
        catch (OperationCanceledException)
        {
            RollbackStateLine = "Check cancelled — nothing was searched.";
        }
        catch (Exception ex)
        {
            RollbackStateLine = $"The rollback check failed ({ex.GetType().Name}): {ex.Message}";
        }
        finally
        {
            IsChecking = false;
            Raise(nameof(CanOpenRollbackSheet));
        }
    }

    public void OpenRollbackSheet()
    {
        if (_actions is null)
        {
            RollbackStateLine = "Driver actions aren't wired in this build — this page stays read-only.";
            return;
        }

        if (_rollbackPreview is null)
        {
            RollbackStateLine = "Check for a rollback target first.";
            return;
        }

        var template = ActionRegistry.Find("driver_rollback");
        if (template is null || template.Status != TemplateStatus.Active)
        {
            RollbackStateLine = "Driver rollback is unavailable in this build — the preview stays informational.";
            return;
        }

        var sheet = new DriverSheetViewModel(_rollbackPreview, template, _actions.Dispatcher)
        {
            ViewHistory = _actions.ViewHistory,
        };
        _actions.Host.Show(sheet);
    }

    // Vendor link-outs leave the app (05: official pages only, and
    // Sentinel vouches for nothing past the click).
    public void OpenLink(string? url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
        {
            return;
        }

        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = uri.AbsoluteUri,
                UseShellExecute = true,
            });
        }
        catch (System.ComponentModel.Win32Exception)
        {
            UpdateStateLine = $"Could not open the vendor page — open this address yourself: {uri.AbsoluteUri}";
        }
    }

    public sealed record DriversSnapshot(
        string Summary,
        string Coverage,
        IReadOnlyList<DriverProblemRow> Problems,
        IReadOnlyList<DriverRow> Drivers,
        IReadOnlyList<TopologyDisk> Topology,
        DateTime CollectedUtc,
        string ChkdskLine = "");
}
