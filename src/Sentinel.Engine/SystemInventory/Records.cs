namespace Sentinel.Engine.SystemInventory;

public sealed record ProcessRecord(
    int Id,
    string Name,
    string? Path,
    string? Company,
    string? Product,
    DateTime? StartTimeUtc,
    long WorkingSetBytes,
    // T51: parent from the ToolHelp snapshot (null off-Windows or
    // when the parent exited mid-enumeration — never guessed).
    int? ParentId = null,
    string? ParentName = null);

// P21: per-arrival identity binding (name + start + path from one
// handle). PID-only sweeps keep the 2s cadence inside the ≤2%
// budget; this binds the arrivals.
public sealed record ProcessIdentity(
    int Pid,
    string Name,
    DateTime? StartUtc,
    string? ExePath);

// P27: CPU% of one top-memory process over the sample window.
// Null = exited or protected on resample. Percent is of total
// machine capacity, like every other CPU number in the app.
public sealed record ProcessCpuSample(
    int Id,
    string Name,
    double? CpuPercent);

public sealed record StartupRecord(
    string Name,
    string Location,
    string Command,
    bool? Enabled);

public sealed record ServiceRecord(
    string Name,
    string DisplayName,
    string Status,
    string StartType);

public sealed record DriverRecord(
    string DeviceName,
    string? DriverVersion,
    string? DriverDate,
    string? Signer,
    string? Status,
    string? HardwareId);

public sealed record EventRecord(
    string Log,
    int Id,
    string Level,
    DateTime TimeUtc,
    string Provider,
    string Message);

public sealed record TargetedEventRecord(
    string Log,
    long RecordId,
    int Id,
    string Level,
    DateTime TimeUtc,
    string Provider,
    string Message,
    IReadOnlyList<string> Properties);

public sealed record DeviceProblemRecord(
    string DeviceId,
    string Name,
    int ErrorCode,
    string ErrorName,
    string? Status);

// T51: one scheduled task (schtasks list view). Triggers/Actions
// come from the on-demand XML detail, not the list.
public sealed record ScheduledTaskRecord(
    string TaskName,
    string? NextRunTime,
    string? Status,
    string? LogonMode);

// T51: on-demand detail for one task (schtasks /xml). Commands
// are shown for inspection; Sentinel never runs them.
public sealed record ScheduledTaskDetail(
    string TaskName,
    IReadOnlyList<string> Actions,
    IReadOnlyList<string> Triggers,
    string? Author,
    bool Hidden);

// T51: browser extension MANIFEST metadata only (name, version,
// permissions, content-script presence). Profile content
// (history, cookies, storage, page data) is never read —
// collectors only open manifest.json/extension-registry files.
public sealed record BrowserExtensionRecord(
    string Browser,
    string Profile,
    string Id,
    string Name,
    string Version,
    IReadOnlyList<string> Permissions,
    bool HasContentScripts,
    string ManifestPath);

// T51: WMI event-subscription persistence (root\subscription).
// Filters that fire consumers on system events — rare enough
// that every row carries a check-first suspicion note.
public sealed record WmiFilterRecord(
    string Name,
    string? Query,
    string? QueryLanguage);

public sealed record WmiBindingRecord(
    string Filter,
    string Consumer);

// T51: one TCP connection (endpoint metadata only — no packet
// content, ever). Pid 0 rows are TIME_WAIT/ownerless leftovers
// the stack attributes to nobody; kept with Pid 0, not dropped.
public sealed record TcpConnectionRecord(
    int Pid,
    string Local,
    string Remote,
    string State);

// Disk → partition → volume topology. A partition without a drive
// letter (recovery, EFI) has a null Volume — reported, not invented.
// Drive letters alone are never the identity: numbers + paths join.
public sealed record VolumeRecord(
    string? DriveLetter,
    string? FileSystem,
    string? Label,
    long? SizeBytes,
    long? SizeRemainingBytes,
    string HealthStatus,
    string Path);

public sealed record PartitionRecord(
    uint PartitionNumber,
    long? SizeBytes,
    string? DriveLetter,
    string? Type,
    bool IsBoot,
    bool IsSystem,
    VolumeRecord? Volume);

public sealed record DiskTopologyRecord(
    uint DiskNumber,
    string Name,
    string BusType,
    string HealthStatus,
    string PartitionStyle,
    long? SizeBytes,
    bool IsBoot,
    IReadOnlyList<PartitionRecord> Partitions,
    string? PnpDeviceId = null);

public sealed record BatteryRecord(
    string Name,
    int? ChargePercent,
    string? Status,
    long? FullChargedCapacityMWh,
    long? DesignCapacityMWh,
    int? CycleCount);

public sealed record DiskHealthRecord(
    string Name,
    string MediaType,
    string HealthStatus,
    string OperationalStatus);

// Defender observation (read-only WMI). Null = property absent on
// this platform build, reported — never defaulted to "protected".
public sealed record DefenderStatusRecord(
    bool? AntivirusEnabled,
    bool? RealTimeProtectionEnabled,
    bool? BehaviorMonitorEnabled,
    string? TamperProtectionSource,
    string? EngineVersion,
    string? SignatureVersion,
    DateTime? SignatureLastUpdatedUtc,
    int? SignatureAgeDays,
    DateTime? LastQuickScanUtc,
    DateTime? LastFullScanUtc,
    int? QuickScanAgeDays,
    int? FullScanAgeDays);

public sealed record DefenderDetectionRecord(
    string ThreatName,
    int ThreatId,
    string Severity,
    string Category,
    string? Path,
    DateTime? DetectedUtc,
    string? ActionTaken,
    bool PendingAction);

// T52: one CURRENT quarantine entry from `MpCmdRun -Restore
// -ListAll` (never inferred from old detection history). Name is
// the restore identity (exact match required); Threat/Path/
// Detected are best-effort captures from the list output; Raw
// keeps the whole block for display and debugging.
public sealed record QuarantineRecord(
    string Name,
    string? Threat,
    string? Path,
    string? Detected,
    string Raw);

// Local static evidence for explicitly selected files (02 §9 "Check
// a file"). Everything is computed on-device; nothing is uploaded.
// Signed=true means WinVerifyTrust verified the file (embedded OR
// catalog signature); Signed=false is "not verified", never a
// verdict — unsigned includes every freshly built binary.
public sealed record StaticFileEvidenceRecord(
    string Path,
    bool Exists,
    long? LengthBytes,
    string? Sha256,
    bool Signed,
    string? SignerSubject,
    string? SignerIssuer,
    string? Detail);
