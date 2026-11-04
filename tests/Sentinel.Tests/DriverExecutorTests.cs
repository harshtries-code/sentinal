using Sentinel.Engine.Actions;
using Sentinel.Engine.Drivers;
using Sentinel.Engine.Policy;
using Sentinel.Engine.SystemInventory;
using Sentinel.Store;

namespace Sentinel.Tests;

// D42: driver update/rollback executors, the blocklist store, the DCU
// parser and WU title matching. Every live operation runs through
// scripted IDriverOps fakes — these tests prove the DECISIONS (refuse
// vs proceed, verify, auto-rollback, block) without touching Windows.
// The live WindowsDriverOps paths run in the VM dangerous-ops battery.
public sealed class DriverExecutorTests : IDisposable
{
    private const string DeviceId = @"PCI\VEN_8086&DEV_9BC5\3&11583659&0&10";

    private readonly string _root;
    private bool _disposed;

    public DriverExecutorTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "sentinel-d42-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch
        {
        }
    }

    // ---- fakes ----

    private sealed class FakeOps : IDriverOps
    {
        public Func<string, DeviceStatus> ReadDeviceFunc { get; set; } =
            id => new DeviceStatus(true, 0, null, 0, "Intel UHD", "30.0.100.9805",
                "09/25/2021", ["PCI\\VEN_8086&DEV_9BC5"]);

        public List<DriverRecord> Installed { get; } = [];

        public List<StorePackage> Store { get; } = [];

        public Func<string, string?, IReadOnlyList<string>, IReadOnlyList<DriverCandidate>> SearchFunc { get; set; } =
            (_, _, _) => [];

        public Func<string, string, InstallResult> InstallWuFunc { get; set; } =
            (_, _) => new InstallResult(true, false, "fake installed");

        public Func<string, InstallResult> InstallStoreFunc { get; set; } =
            inf => new InstallResult(true, false, $"{inf} fake installed");

        public Func<OemScanSet> ScanFunc { get; set; } = () => new OemScanSet([], "no catalogue");

        public Func<InstallResult> ApplyOemFunc { get; set; } =
            () => new InstallResult(true, false, "fake applied");

        public bool Network { get; set; } = true;

        public int WuInstallCalls { get; private set; }

        public int StoreInstallCalls { get; private set; }

        public List<string> StoreInstalled { get; } = [];

        public DeviceStatus ReadDevice(string deviceId) => ReadDeviceFunc(deviceId);

        public IReadOnlyList<DriverRecord> EnumInstalledDrivers() => Installed;

        public IReadOnlyList<StorePackage> EnumStore() => Store;

        public IReadOnlyList<DriverCandidate> SearchWindowsUpdate(
            string deviceId, string? deviceName, IReadOnlyList<string> hardwareIds) =>
            SearchFunc(deviceId, deviceName, hardwareIds);

        public InstallResult InstallWindowsUpdate(string deviceId, string catalogueId)
        {
            WuInstallCalls++;
            return InstallWuFunc(deviceId, catalogueId);
        }

        public InstallResult InstallStorePackage(string publishedInf)
        {
            StoreInstallCalls++;
            StoreInstalled.Add(publishedInf);
            return InstallStoreFunc(publishedInf);
        }

        public OemScanSet ScanOemCatalogue() => ScanFunc();

        public InstallResult ApplyOemCatalogue() => ApplyOemFunc();

        public bool IsNetworkAvailable() => Network;
    }

    private sealed class FakeSr : ISrClient
    {
        public long NextSequence { get; set; } = 4242;

        public bool BeginFails { get; set; }

        public bool EndFails { get; set; }

        public int Begins { get; private set; }

        public int Ends { get; private set; }

        public (long? Sequence, string? Error) Begin(string description)
        {
            _ = description;
            Begins++;
            return BeginFails ? (null, "SR disabled in fixture") : (NextSequence++, null);
        }

        public string? End(long sequence)
        {
            _ = sequence;
            Ends++;
            return EndFails ? "END failed in fixture" : null;
        }
    }

    private sealed class CapturingAudit : IActionAuditSink
    {
        public List<AuditDraft> Drafts { get; } = [];

        public bool Fail { get; set; }

        public bool TryAppend(AuditDraft draft, out long seq, out string error)
        {
            if (Fail)
            {
                seq = -1;
                error = "store unavailable";
                return false;
            }

            Drafts.Add(draft);
            seq = Drafts.Count;
            error = string.Empty;
            return true;
        }
    }

    private sealed class MapResolver : IBrokerIdResolver
    {
        private readonly Dictionary<string, string> _map;

        public MapResolver(Dictionary<string, string> map)
        {
            _map = map;
        }

        public bool TryResolve(string brokerId, out string path) =>
            _map.TryGetValue(brokerId, out path!);
    }

    private sealed class ThrowingResolver : IBrokerIdResolver
    {
        public bool TryResolve(string brokerId, out string path) =>
            throw new InvalidOperationException("resolver exploded");
    }

    private sealed class FixedLevels : IPermissionLevels
    {
        private readonly Dictionary<string, PermissionLevel> _levels;

        public FixedLevels(Dictionary<string, PermissionLevel> levels)
        {
            _levels = levels;
        }

        public PermissionLevel LevelFor(string module) =>
            _levels.TryGetValue(module, out var level) ? level : PermissionLevel.L0;
    }

    // ---- builders ----

    private static ActionTemplate Template(string id) =>
        ActionRegistry.All.First(t => t.Id == id);

    private static DriverTargetAux UpdateAux(
        string source = "windows-update",
        string? catalogueId = "cat-1",
        string? version = "31.0.101.2121",
        string? previousInf = "oem12.inf",
        string? previousVersion = "30.0.100.9805") =>
        new(previousInf, previousVersion, "09/25/2021", source, version, catalogueId, null, null);

    private static DriverTargetAux RollbackAux(
        string targetInf = "oem12.inf",
        string? badVersion = "31.0.101.2121",
        string badSource = "windows-update",
        string? previousVersion = "30.0.100.9805") =>
        new(targetInf, previousVersion, "09/25/2021", badSource, null, null, targetInf, badVersion);

    private static ActionTarget DeviceTarget(
        DriverTargetAux aux, string brokerId = "d:1", string deviceId = DeviceId) =>
        new(brokerId, deviceId, "device", RiskTier.Review, 0, 0, null, aux.ToJson());

    private static ActionApproval Approval(string templateId, params ActionTarget[] targets) =>
        new(templateId, targets, [], [], 1, DateTimeOffset.UtcNow,
            ActionActors.User, Guid.NewGuid().ToString("N"));

    private static DeviceStatus Status(
        string? version = "30.0.100.9805",
        bool present = true,
        int problem = 0,
        string? problemName = null) =>
        new(present, problem, problemName, 0, "Intel UHD", version, "09/25/2021",
            ["PCI\\VEN_8086&DEV_9BC5"]);

    private static StorePackage StorePkg(
        string published = "oem12.inf",
        string? version = "09/25/2021 30.0.100.9805",
        string? provider = "Intel Corporation") =>
        new(published, "igcc.inf", provider, "Display", "{guid}",
            version, "Microsoft Windows Hardware Compatibility Publisher", null);

    private static DriverCandidate WuCandidate(
        string version = "31.0.101.2121",
        string catalogueId = "cat-1") =>
        new(DriverSource.WindowsUpdate, null, version, null, "Windows Update",
            ["PCI\\VEN_8086&DEV_9BC5"], catalogueId, null);

    private DriverBlocklist NewBlocklist(string? name = null)
    {
        string path = Path.Combine(_root, name ?? Guid.NewGuid().ToString("N") + ".db");
        return new DriverBlocklist(() => new PassportDb(path));
    }

    // The standard green-path fixture: device on 30.x, oem12.inf in
    // the store, WU offering cat-1 at 31.x, live version flips to 31.x
    // after install.
    private static void GivenGreenWU(FakeOps ops)
    {
        string liveVersion = "30.0.100.9805";
        ops.ReadDeviceFunc = _ => Status(liveVersion);
        ops.Store.Add(StorePkg());
        ops.SearchFunc = (_, _, _) => [WuCandidate()];
        ops.InstallWuFunc = (_, _) =>
        {
            liveVersion = "31.0.101.2121";
            return new InstallResult(true, false, "installed");
        };
    }

    private static DriverUpdateExecutor UpdateExecutor(
        FakeOps ops, FakeSr sr, DriverBlocklist blocklist, CapturingAudit audit,
        bool elevated = true, int? disableSr = null) =>
        new(ops, sr, () => blocklist, audit, () => elevated, () => disableSr);

    private static DriverRollbackExecutor RollbackExecutor(
        FakeOps ops, FakeSr sr, DriverBlocklist blocklist, CapturingAudit audit,
        bool elevated = true, int? disableSr = null) =>
        new(ops, sr, () => blocklist, audit, () => elevated, () => disableSr);

    // ---- aux parsing ----

    [Fact]
    public void Aux_ParseRoundTrip()
    {
        var aux = UpdateAux();
        var parsed = DriverTargetAux.Parse(aux.ToJson());
        Assert.Equal(aux, parsed);
    }

    [Fact]
    public void Aux_ParseMalformed_ReturnsNull()
    {
        Assert.Null(DriverTargetAux.Parse("{not json"));
        Assert.Null(DriverTargetAux.Parse(null));
        Assert.Null(DriverTargetAux.Parse("  "));
    }

    // ---- update: happy path ----

    [Fact]
    public async Task Update_HappyPathWU_CompletedAndVerified()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        var sr = new FakeSr();
        var audit = new CapturingAudit();
        var executor = UpdateExecutor(ops, sr, NewBlocklist(), audit);

        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux())),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Completed, result.Status);
        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Done, item.Status);
        Assert.Contains("30.0.100.9805 → 31.0.101.2121", item.Detail);
        Assert.Contains("RestorePoint:4242", item.Detail);
        Assert.True(item.UndoAvailable);
        Assert.Equal("Ok/None", item.RevalidationVerdict);
        Assert.Equal(1, ops.WuInstallCalls);
        Assert.Equal(0, ops.StoreInstallCalls);
        Assert.Equal(1, sr.Begins);
        Assert.Equal(1, sr.Ends);
        var draft = Assert.Single(audit.Drafts);
        Assert.Equal("RestorePoint:4242", draft.BackupRef);
        Assert.Equal("Available:Rollback:oem12.inf", draft.UndoState);
    }

    [Fact]
    public async Task Update_WrongTemplate_Failed()
    {
        var executor = UpdateExecutor(new FakeOps(), new FakeSr(), NewBlocklist(), new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval("clean_items_to_vault", DeviceTarget(UpdateAux())),
            Template("clean_items_to_vault"), null, null), CancellationToken.None);
        Assert.Equal(BatchStatus.Failed, result.Status);
        Assert.Empty(result.Items);
    }

    [Fact]
    public async Task Update_WrongKind_Refused()
    {
        var ops = new FakeOps();
        var sr = new FakeSr();
        var executor = UpdateExecutor(ops, sr, NewBlocklist(), new CapturingAudit());
        var target = DeviceTarget(UpdateAux()) with { Kind = "file" };
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, target),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, result.Status);
        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Equal(0, sr.Begins);
        Assert.Equal(0, ops.WuInstallCalls);
    }

    [Fact]
    public async Task Update_RebindMismatch_Refused()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        var sr = new FakeSr();
        var executor = UpdateExecutor(ops, sr, NewBlocklist(), new CapturingAudit());
        var resolver = new MapResolver(new Dictionary<string, string>
        {
            ["d:1"] = @"PCI\VEN_10DE&DEV_9999\other",
        });
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux())),
            Template(DriverUpdateExecutor.TemplateId), resolver, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Contains("no longer resolves", item.Detail);
        Assert.Equal(0, sr.Begins);
    }

    [Fact]
    public async Task Update_MalformedAux_Refused()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        var sr = new FakeSr();
        var executor = UpdateExecutor(ops, sr, NewBlocklist(), new CapturingAudit());
        var target = DeviceTarget(UpdateAux()) with { AuxJson = "{broken" };
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, target),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Equal("Aux/Malformed", item.RevalidationVerdict);
        Assert.Equal(0, sr.Begins);
    }

    [Fact]
    public async Task Update_Unelevated_RefusedWithRelaunch()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        var sr = new FakeSr();
        var executor = UpdateExecutor(ops, sr, NewBlocklist(), new CapturingAudit(), elevated: false);
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux())),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Contains("relaunch Sentinel as administrator", item.Detail);
        Assert.Equal("Elevation/Required", item.RevalidationVerdict);
        Assert.Equal(0, sr.Begins);
        Assert.Equal(0, ops.WuInstallCalls);
    }

    [Fact]
    public async Task Update_RestoreCapabilityOff_Refused()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        var sr = new FakeSr();
        var executor = UpdateExecutor(ops, sr, NewBlocklist(), new CapturingAudit(), disableSr: 1);
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux())),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Contains("System Protection is turned off", item.Detail);
        Assert.Equal(0, sr.Begins);
    }

    [Fact]
    public async Task Update_RestoreBeginFails_Failed()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        var sr = new FakeSr { BeginFails = true };
        var executor = UpdateExecutor(ops, sr, NewBlocklist(), new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux())),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Failed, result.Status);
        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Failed, item.Status);
        Assert.Contains("restore point could not be created", item.Detail);
        Assert.Equal(0, ops.WuInstallCalls);
    }

    [Fact]
    public async Task Update_DeviceGone_Refused()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        ops.ReadDeviceFunc = _ => Status(present: false);
        var sr = new FakeSr();
        var executor = UpdateExecutor(ops, sr, NewBlocklist(), new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux())),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Equal("Device/Gone", item.RevalidationVerdict);
        Assert.Equal(0, ops.WuInstallCalls);
        // Restore point was created, then closed without use.
        Assert.Equal(1, sr.Begins);
        Assert.Equal(1, sr.Ends);
    }

    [Fact]
    public async Task Update_VersionUnknown_Refused()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        ops.ReadDeviceFunc = _ => Status(version: null);
        var executor = UpdateExecutor(ops, new FakeSr(), NewBlocklist(), new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux())),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Equal("Identity/Unknown", item.RevalidationVerdict);
        Assert.Equal(0, ops.WuInstallCalls);
    }

    [Fact]
    public async Task Update_NoIdentityMatch_Refused()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        ops.Store.Clear(); // store is empty: no rollback target
        var executor = UpdateExecutor(ops, new FakeSr(), NewBlocklist(), new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux())),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Equal("Identity/NoMatch", item.RevalidationVerdict);
        Assert.Equal(0, ops.WuInstallCalls);
    }

    [Fact]
    public async Task Update_NoCatalogueId_Refused()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        var executor = UpdateExecutor(ops, new FakeSr(), NewBlocklist(), new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux(catalogueId: null))),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Equal("Candidate/NoCatalogueId", item.RevalidationVerdict);
        Assert.Equal(0, ops.WuInstallCalls);
    }

    [Fact]
    public async Task Update_NetworkDown_Refused()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        ops.Network = false;
        var executor = UpdateExecutor(ops, new FakeSr(), NewBlocklist(), new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux())),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Equal("Network/Down", item.RevalidationVerdict);
    }

    [Fact]
    public async Task Update_CandidateStale_Refused()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        ops.SearchFunc = (_, _, _) => [WuCandidate(catalogueId: "cat-other")];
        var executor = UpdateExecutor(ops, new FakeSr(), NewBlocklist(), new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux())),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Equal("Candidate/Stale", item.RevalidationVerdict);
        Assert.Equal(0, ops.WuInstallCalls);
    }

    [Fact]
    public async Task Update_CandidateUnversioned_Refused()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        ops.SearchFunc = (_, _, _) => [WuCandidate(version: string.Empty)];
        var executor = UpdateExecutor(ops, new FakeSr(), NewBlocklist(), new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux(version: null))),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Equal("Candidate/Unversioned", item.RevalidationVerdict);
        Assert.Contains("blind install", item.Detail);
    }

    [Fact]
    public async Task Update_CandidateChanged_Refused()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        ops.SearchFunc = (_, _, _) => [WuCandidate(version: "31.0.101.9999")];
        var executor = UpdateExecutor(ops, new FakeSr(), NewBlocklist(), new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux())),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Equal("Candidate/Changed", item.RevalidationVerdict);
        Assert.Equal(0, ops.WuInstallCalls);
    }

    [Fact]
    public async Task Update_BlockedCandidate_Refused()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        var blocklist = NewBlocklist();
        blocklist.Add(DriverSource.WindowsUpdate, "31.0.101.2121", DeviceId, "previously bad");
        var executor = UpdateExecutor(ops, new FakeSr(), blocklist, new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux())),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Equal("Candidate/Ineligible", item.RevalidationVerdict);
        Assert.Contains("blocked before", item.Detail);
        Assert.Equal(0, ops.WuInstallCalls);
    }

    [Fact]
    public async Task Update_OlderCandidate_Refused()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        ops.SearchFunc = (_, _, _) => [WuCandidate(version: "29.0.100.0000")];
        var executor = UpdateExecutor(ops, new FakeSr(), NewBlocklist(), new CapturingAudit());
        var aux = UpdateAux(version: "29.0.100.0000");
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(aux)),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Contains("older than installed", item.Detail);
    }

    [Fact]
    public async Task Update_InstallFails_FailedWithRestorePoint()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        ops.InstallWuFunc = (_, _) => new InstallResult(false, false, "WU error 0x80240022");
        var executor = UpdateExecutor(ops, new FakeSr(), NewBlocklist(), new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux())),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Failed, result.Status);
        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Failed, item.Status);
        Assert.Contains("0x80240022", item.Detail);
        Assert.Contains("RestorePoint:4242", item.Detail);
        // Nothing changed, so no auto-rollback is attempted.
        Assert.Equal(0, ops.StoreInstallCalls);
    }

    [Fact]
    public async Task Update_VerifyFails_AutoRollbackAndBlock()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        // Install "succeeds" but the live version never changes.
        ops.InstallWuFunc = (_, _) => new InstallResult(true, false, "installed");
        ops.ReadDeviceFunc = _ => Status("30.0.100.9805");
        var blocklist = NewBlocklist();
        var executor = UpdateExecutor(ops, new FakeSr(), blocklist, new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux())),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Failed, result.Status);
        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Failed, item.Status);
        Assert.Equal("Verify/Failed", item.RevalidationVerdict);
        Assert.Contains("Verification failed", item.Detail);
        Assert.Contains("automatically reinstalled", item.Detail);
        Assert.Contains("RestorePoint:4242", item.Detail);
        Assert.Equal(["oem12.inf"], ops.StoreInstalled);
        Assert.True(blocklist.IsBlocked(DriverSource.WindowsUpdate, "31.0.101.2121"));
    }

    [Fact]
    public async Task Update_RollbackFails_ReportsManualRecovery()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        ops.InstallWuFunc = (_, _) => new InstallResult(true, false, "installed");
        ops.ReadDeviceFunc = _ => Status("30.0.100.9805");
        ops.InstallStoreFunc = _ => new InstallResult(false, false, "pnputil error");
        var blocklist = NewBlocklist();
        var executor = UpdateExecutor(ops, new FakeSr(), blocklist, new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux())),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Failed, item.Status);
        Assert.Contains("ALSO failed", item.Detail);
        Assert.Contains("manual recovery", item.Detail);
        Assert.True(blocklist.IsBlocked(DriverSource.WindowsUpdate, "31.0.101.2121"));
    }

    [Fact]
    public async Task Update_OemHappyPath_VerifiesNoNewProblem()
    {
        var ops = new FakeOps();
        string liveVersion = "30.0.100.9805";
        ops.ReadDeviceFunc = _ => Status(liveVersion);
        ops.Store.Add(StorePkg());
        ops.ScanFunc = () => new OemScanSet(
            ["Intel Graphics 31.0.101.2121", "BIOS 1.2.3"], "2 update(s)");
        bool applied = false;
        ops.ApplyOemFunc = () =>
        {
            applied = true;
            liveVersion = "31.0.101.2121";
            return new InstallResult(true, true, "applied");
        };
        var executor = UpdateExecutor(ops, new FakeSr(), NewBlocklist(), new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId,
                DeviceTarget(UpdateAux(source: "oem-catalogue", catalogueId: null, version: null))),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        Assert.True(applied);
        Assert.Equal(BatchStatus.Completed, result.Status);
        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Done, item.Status);
        Assert.Contains("2 update(s)", item.Detail);
        Assert.Contains("reboot is pending", item.Detail);
    }

    [Fact]
    public async Task Update_OemNoUpdates_Refused()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        ops.ScanFunc = () => new OemScanSet([], "0 updates");
        var executor = UpdateExecutor(ops, new FakeSr(), NewBlocklist(), new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId,
                DeviceTarget(UpdateAux(source: "oem-catalogue", catalogueId: null, version: null))),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, result.Status);
    }

    [Fact]
    public async Task Update_OemNewProblem_RollsBack()
    {
        var ops = new FakeOps();
        int reads = 0;
        ops.ReadDeviceFunc = _ => ++reads <= 1 ? Status("30.0.100.9805") : Status("31.0.101.2121", problem: 28);
        ops.Store.Add(StorePkg());
        ops.ScanFunc = () => new OemScanSet(["Intel Graphics 31.0.101.2121"], "1 update");
        // Rollback reinstall restores the old version.
        ops.InstallStoreFunc = _ =>
        {
            ops.ReadDeviceFunc = _ => Status("30.0.100.9805");
            return new InstallResult(true, false, "reinstalled");
        };
        var executor = UpdateExecutor(ops, new FakeSr(), NewBlocklist(), new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId,
                DeviceTarget(UpdateAux(source: "oem-catalogue", catalogueId: null, version: null))),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Failed, item.Status);
        Assert.Contains("new problem code 28", item.Detail);
        Assert.Equal(["oem12.inf"], ops.StoreInstalled);
    }

    [Fact]
    public async Task Update_LinkOutSource_Refused()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        var executor = UpdateExecutor(ops, new FakeSr(), NewBlocklist(), new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId,
                DeviceTarget(UpdateAux(source: "vendor-link-out"))),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Equal("Source/LinkOut", item.RevalidationVerdict);
        Assert.Equal(0, ops.WuInstallCalls);
    }

    [Fact]
    public async Task Update_AuditGap_DoneWithWarning()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        var audit = new CapturingAudit { Fail = true };
        var executor = UpdateExecutor(ops, new FakeSr(), NewBlocklist(), audit);
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux())),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        // Verified-good changes are never un-done over a logging gap.
        Assert.Equal(BatchStatus.Completed, result.Status);
        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Done, item.Status);
        Assert.Equal("Ok/AuditGap", item.RevalidationVerdict);
        Assert.Contains("WARNING", item.Detail);
    }

    [Fact]
    public async Task Update_Cancelled_MarksRemaining()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        var executor = UpdateExecutor(ops, new FakeSr(), NewBlocklist(), new CapturingAudit());
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId,
                DeviceTarget(UpdateAux()), DeviceTarget(UpdateAux(), "d:2")),
            Template(DriverUpdateExecutor.TemplateId), null, null), cts.Token);

        Assert.Equal(BatchStatus.Cancelled, result.Status);
        Assert.All(result.Items, i => Assert.Equal(ItemStatus.Cancelled, i.Status));
        Assert.Equal(0, ops.WuInstallCalls);
    }

    [Fact]
    public async Task Update_BatchPartial_OneDoneOneRefused()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        var executor = UpdateExecutor(ops, new FakeSr(), NewBlocklist(), new CapturingAudit());
        var bad = DeviceTarget(UpdateAux(), "d:2") with { Kind = "file" };
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux()), bad),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Partial, result.Status);
        Assert.Equal(ItemStatus.Done, result.Items[0].Status);
        Assert.Equal(ItemStatus.Refused, result.Items[1].Status);
    }

    [Fact]
    public async Task Update_ResolverThrows_BackstopFailed()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        var audit = new CapturingAudit();
        var executor = UpdateExecutor(ops, new FakeSr(), NewBlocklist(), audit);
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux())),
            Template(DriverUpdateExecutor.TemplateId), new ThrowingResolver(), null),
            CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Failed, item.Status);
        Assert.Contains("Unexpected failure", item.Detail);
        Assert.Equal(0, ops.WuInstallCalls);
        Assert.Single(audit.Drafts);
    }

    [Fact]
    public async Task Update_RestoreEndFails_AuditedSeparately()
    {
        var ops = new FakeOps();
        GivenGreenWU(ops);
        var sr = new FakeSr { EndFails = true };
        var audit = new CapturingAudit();
        var executor = UpdateExecutor(ops, sr, NewBlocklist(), audit);
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux())),
            Template(DriverUpdateExecutor.TemplateId), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Completed, result.Status);
        Assert.Equal(2, audit.Drafts.Count);
        Assert.Contains("close reported", audit.Drafts[1].Detail);
    }

    // ---- rollback ----

    private static void GivenGreenRollback(FakeOps ops)
    {
        string liveVersion = "31.0.101.2121"; // the bad one
        ops.ReadDeviceFunc = _ => Status(liveVersion);
        ops.Store.Add(StorePkg("oem12.inf")); // previous
        ops.Store.Add(StorePkg("oem45.inf", "01/10/2022 31.0.101.2121", "Intel Corporation"));
        ops.InstallStoreFunc = _ =>
        {
            liveVersion = "30.0.100.9805";
            return new InstallResult(true, false, "reinstalled");
        };
    }

    [Fact]
    public async Task Rollback_HappyPath_BlocksBad()
    {
        var ops = new FakeOps();
        GivenGreenRollback(ops);
        var sr = new FakeSr();
        var audit = new CapturingAudit();
        var blocklist = NewBlocklist();
        var executor = RollbackExecutor(ops, sr, blocklist, audit);
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverRollbackExecutor.TemplateId, DeviceTarget(RollbackAux())),
            Template(DriverRollbackExecutor.TemplateId), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Completed, result.Status);
        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Done, item.Status);
        Assert.Contains("oem12.inf", item.Detail);
        Assert.Contains("blocked from future offers", item.Detail);
        Assert.False(item.UndoAvailable);
        Assert.Equal(["oem12.inf"], ops.StoreInstalled);
        Assert.True(blocklist.IsBlocked(DriverSource.WindowsUpdate, "31.0.101.2121"));
        var draft = Assert.Single(audit.Drafts);
        Assert.Equal("RestorePoint:4242", draft.BackupRef);
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("")]
    [InlineData("mystery-channel")]
    public async Task Rollback_UnknownSource_BlocksBothChannels(string badSource)
    {
        var ops = new FakeOps();
        GivenGreenRollback(ops);
        var blocklist = NewBlocklist();
        var executor = RollbackExecutor(ops, new FakeSr(), blocklist, new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverRollbackExecutor.TemplateId, DeviceTarget(RollbackAux(badSource: badSource))),
            Template(DriverRollbackExecutor.TemplateId), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Completed, result.Status);
        Assert.True(blocklist.IsBlocked(DriverSource.WindowsUpdate, "31.0.101.2121"));
        Assert.True(blocklist.IsBlocked(DriverSource.OemCatalogue, "31.0.101.2121"));
    }

    [Fact]
    public async Task Rollback_KnownSource_BlocksOnlyThatChannel()
    {
        var ops = new FakeOps();
        GivenGreenRollback(ops);
        var blocklist = NewBlocklist();
        var executor = RollbackExecutor(ops, new FakeSr(), blocklist, new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverRollbackExecutor.TemplateId,
                DeviceTarget(RollbackAux(badSource: "oem-catalogue"))),
            Template(DriverRollbackExecutor.TemplateId), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Completed, result.Status);
        Assert.True(blocklist.IsBlocked(DriverSource.OemCatalogue, "31.0.101.2121"));
        Assert.False(blocklist.IsBlocked(DriverSource.WindowsUpdate, "31.0.101.2121"));
    }

    [Fact]
    public async Task Rollback_WrongTemplate_Failed()
    {
        var executor = RollbackExecutor(new FakeOps(), new FakeSr(), NewBlocklist(), new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval("clean_items_to_vault", DeviceTarget(RollbackAux())),
            Template("clean_items_to_vault"), null, null), CancellationToken.None);
        Assert.Equal(BatchStatus.Failed, result.Status);
    }

    [Theory]
    [InlineData("evil.sys")]
    [InlineData("../oem1.inf")]
    [InlineData("oem1.inf.exe")]
    [InlineData("C:\\Windows\\INF\\oem1.inf")]
    [InlineData("")]
    public async Task Rollback_BadInfName_Refused(string inf)
    {
        var ops = new FakeOps();
        GivenGreenRollback(ops);
        var sr = new FakeSr();
        var executor = RollbackExecutor(ops, sr, NewBlocklist(), new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverRollbackExecutor.TemplateId, DeviceTarget(RollbackAux(inf))),
            Template(DriverRollbackExecutor.TemplateId), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Equal("Target/BadName", item.RevalidationVerdict);
        Assert.Equal(0, sr.Begins);
        Assert.Equal(0, ops.StoreInstallCalls);
    }

    [Fact]
    public async Task Rollback_Unelevated_Refused()
    {
        var ops = new FakeOps();
        GivenGreenRollback(ops);
        var executor = RollbackExecutor(ops, new FakeSr(), NewBlocklist(), new CapturingAudit(), elevated: false);
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverRollbackExecutor.TemplateId, DeviceTarget(RollbackAux())),
            Template(DriverRollbackExecutor.TemplateId), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Equal("Elevation/Required", item.RevalidationVerdict);
    }

    [Fact]
    public async Task Rollback_TargetVanished_Refused()
    {
        var ops = new FakeOps();
        GivenGreenRollback(ops);
        ops.Store.RemoveAll(p => p.PublishedName == "oem12.inf");
        var executor = RollbackExecutor(ops, new FakeSr(), NewBlocklist(), new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverRollbackExecutor.TemplateId, DeviceTarget(RollbackAux())),
            Template(DriverRollbackExecutor.TemplateId), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Equal("Target/Vanished", item.RevalidationVerdict);
        Assert.Equal(0, ops.StoreInstallCalls);
    }

    [Fact]
    public async Task Rollback_InstallFails_Failed()
    {
        var ops = new FakeOps();
        GivenGreenRollback(ops);
        ops.InstallStoreFunc = _ => new InstallResult(false, false, "pnputil error 0xE0000247");
        var executor = RollbackExecutor(ops, new FakeSr(), NewBlocklist(), new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverRollbackExecutor.TemplateId, DeviceTarget(RollbackAux())),
            Template(DriverRollbackExecutor.TemplateId), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Failed, item.Status);
        Assert.Contains("0xE0000247", item.Detail);
        Assert.Contains("RestorePoint:4242", item.Detail);
    }

    [Fact]
    public async Task Rollback_StillBad_Failed()
    {
        var ops = new FakeOps();
        GivenGreenRollback(ops);
        // Reinstall "succeeds" but the bad version persists.
        ops.InstallStoreFunc = _ => new InstallResult(true, false, "reinstalled");
        ops.ReadDeviceFunc = _ => Status("31.0.101.2121");
        var blocklist = NewBlocklist();
        var executor = RollbackExecutor(ops, new FakeSr(), blocklist, new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverRollbackExecutor.TemplateId, DeviceTarget(RollbackAux())),
            Template(DriverRollbackExecutor.TemplateId), null, null), CancellationToken.None);

        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Failed, item.Status);
        Assert.Equal("Verify/Failed", item.RevalidationVerdict);
        Assert.Contains("still reports", item.Detail);
    }

    [Fact]
    public async Task Rollback_DeviceGone_Refused()
    {
        var ops = new FakeOps();
        GivenGreenRollback(ops);
        ops.ReadDeviceFunc = _ => Status(present: false);
        var executor = RollbackExecutor(ops, new FakeSr(), NewBlocklist(), new CapturingAudit());
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverRollbackExecutor.TemplateId, DeviceTarget(RollbackAux())),
            Template(DriverRollbackExecutor.TemplateId), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, result.Status);
        Assert.Equal(0, ops.StoreInstallCalls);
    }

    [Fact]
    public async Task Rollback_AuditGap_DoneWithWarning()
    {
        var ops = new FakeOps();
        GivenGreenRollback(ops);
        var audit = new CapturingAudit { Fail = true };
        var executor = RollbackExecutor(ops, new FakeSr(), NewBlocklist(), audit);
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverRollbackExecutor.TemplateId, DeviceTarget(RollbackAux())),
            Template(DriverRollbackExecutor.TemplateId), null, null), CancellationToken.None);

        Assert.Equal(BatchStatus.Completed, result.Status);
        var item = Assert.Single(result.Items);
        Assert.Contains("WARNING", item.Detail);
    }

    [Fact]
    public async Task Rollback_Cancelled()
    {
        var ops = new FakeOps();
        GivenGreenRollback(ops);
        var executor = RollbackExecutor(ops, new FakeSr(), NewBlocklist(), new CapturingAudit());
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var result = await executor.ExecuteAsync(new BatchExecutionRequest(
            Approval(DriverRollbackExecutor.TemplateId, DeviceTarget(RollbackAux())),
            Template(DriverRollbackExecutor.TemplateId), null, null), cts.Token);

        Assert.Equal(BatchStatus.Cancelled, result.Status);
        Assert.Equal(0, ops.StoreInstallCalls);
    }

    // ---- blocklist store ----

    [Fact]
    public void Blocklist_AddPersists_ReloadSees()
    {
        string path = Path.Combine(_root, "bl.db");
        var first = new DriverBlocklist(() => new PassportDb(path));
        first.Add(DriverSource.WindowsUpdate, "31.0.101.2121", DeviceId, "bad");
        first.Add("oem-catalogue", "1.2.3", null, "bad set");

        var second = new DriverBlocklist(() => new PassportDb(path));
        Assert.False(second.LoadedWithFault);
        Assert.True(second.IsBlocked(DriverSource.WindowsUpdate, "31.0.101.2121"));
        Assert.True(second.Keys.Contains("OemCatalogue|1.2.3"));
        Assert.Equal(2, second.Entries.Count);
    }

    [Fact]
    public void Blocklist_CorruptFile_LoadsEmptyWithFault()
    {
        string path = Path.Combine(_root, "corrupt.db");
        // Past SQLite's 100-byte header: this file is corrupt, not empty.
        File.WriteAllText(path, new string('x', 512));
        var list = new DriverBlocklist(() => new PassportDb(path));
        Assert.True(list.LoadedWithFault);
        Assert.NotNull(list.LoadFault);
        Assert.Empty(list.Keys);
    }

    [Fact]
    public void Blocklist_MissingFile_LoadsEmpty()
    {
        string absent = Path.Combine(_root, "absent.db");
        var list = new DriverBlocklist(() => new PassportDb(absent));
        Assert.False(list.LoadedWithFault);
        Assert.Empty(list.Keys);
    }

    [Fact]
    public void Blocklist_Remove_Deletes()
    {
        string path = Path.Combine(_root, "rm.db");
        var list = new DriverBlocklist(() => new PassportDb(path));
        list.Add(DriverSource.WindowsUpdate, "1.0", null, "bad");
        Assert.True(list.Remove("WindowsUpdate|1.0"));
        Assert.False(list.Remove("WindowsUpdate|1.0"));
        Assert.Empty(new DriverBlocklist(() => new PassportDb(path)).Keys);
    }

    [Fact]
    public void Blocklist_KeyFormat_MatchesMatching()
    {
        var candidate = WuCandidate();
        Assert.Equal(
            DriverMatching.BlockKey(candidate),
            DriverBlocklist.BlockKey(candidate.Source, candidate.Version));
    }

    [Theory]
    [InlineData("windows-update", "WindowsUpdate")]
    [InlineData("WU", "WindowsUpdate")]
    [InlineData("oem-catalogue", "OemCatalogue")]
    [InlineData("dcu", "OemCatalogue")]
    [InlineData("vendor-link-out", "VendorLinkOut")]
    [InlineData("WindowsUpdate", "WindowsUpdate")]
    [InlineData("mystery-source", "mystery-source")]
    public void Blocklist_CanonicalSource(string input, string expected)
    {
        Assert.Equal(expected, DriverBlocklist.CanonicalSource(input));
    }

    [Fact]
    public void Blocklist_StringSourceBlock_MatchesEnumLookup()
    {
        // The rollback path records the source as approval text; the
        // matching consults enum-keyed lookups. They must meet.
        var list = NewBlocklist();
        list.Add("windows-update", "31.0.101.2121", DeviceId, "rolled back");
        Assert.True(list.IsBlocked(DriverSource.WindowsUpdate, "31.0.101.2121"));
        Assert.True(list.Keys.Contains("WindowsUpdate|31.0.101.2121"));
    }

    // ---- DCU parser ----

    [Fact]
    public void DcuParser_TitlesAndOther()
    {
        var parsed = DcuParser.Parse(
            "Dell Command Update\n" +
            "BIOS Update 1.2.3\n" +
            "Intel Graphics Driver 31.0.101.2121\n" +
            "Scan complete.\n");
        Assert.Equal(2, parsed.Titles.Count);
        Assert.Contains("BIOS Update 1.2.3", parsed.Titles);
        Assert.True(parsed.OtherLines >= 1);
        Assert.Contains("2 update(s)", parsed.RawSummary);
    }

    [Fact]
    public void DcuParser_Empty()
    {
        var parsed = DcuParser.Parse("  ");
        Assert.Empty(parsed.Titles);
        Assert.Contains("no output", parsed.RawSummary);
    }

    [Fact]
    public void DcuParser_FlagAndPathLinesAreNotTitles()
    {
        var parsed = DcuParser.Parse(
            "/scan -outputlog=C:\\temp\\dcu.log\n" +
            "C:\\Program Files\\Dell\\CommandUpdate\\dcu-cli.exe\n");
        Assert.Empty(parsed.Titles);
    }

    // ---- WU title matching (pure) ----

    [Fact]
    public void WuTitle_TwoSharedTokens_Match()
    {
        Assert.True(WindowsUpdateDrivers.TitleMatchesDevice(
            "Intel UHD Graphics Driver - 31.0.101.2121", "Intel UHD Graphics",
            ["PCI\\VEN_8086&DEV_9BC5"]));
    }

    [Fact]
    public void WuTitle_SingleToken_NoMatch()
    {
        Assert.False(WindowsUpdateDrivers.TitleMatchesDevice(
            "Intel Corporation - Bluetooth - 22.0.0.1", "Intel UHD Graphics",
            ["PCI\\VEN_8086&DEV_9BC5"]));
    }

    [Fact]
    public void WuTitle_HardwareIdSubstring_Match()
    {
        Assert.True(WindowsUpdateDrivers.TitleMatchesDevice(
            "OEM driver for PCI\\VEN_8086&DEV_9BC5 device", null,
            ["PCI\\VEN_8086&DEV_9BC5"]));
    }

    [Fact]
    public void WuTitle_VersionParsedFromTrailingToken()
    {
        Assert.Equal("31.0.101.2121", WindowsUpdateDrivers.TitleVersion(
            "Intel Corporation - Display - 31.0.101.2121"));
        Assert.Equal(string.Empty, WindowsUpdateDrivers.TitleVersion("Some driver update"));
    }

    // ---- dispatch integration ----

    [Fact]
    public async Task Dispatch_ActiveDriverTemplateWithoutExecutor_RefusedNotImplemented()
    {
        var audit = new CapturingAudit();
        var dispatcher = new ActionDispatcher(audit, new FixedLevels(
            new Dictionary<string, PermissionLevel> { ["Drivers"] = PermissionLevel.L2 }));
        var outcome = await dispatcher.DispatchAsync(
            Approval(DriverUpdateExecutor.TemplateId, DeviceTarget(UpdateAux())),
            null, CancellationToken.None);
        Assert.Equal(BatchStatus.Refused, outcome.Status);
        Assert.Equal(RefusalCode.TemplateNotImplemented, outcome.Refusal);
    }
}
