using Sentinel.App.Services;
using Sentinel.Engine.Actions;
using Sentinel.Engine.Policy;
using Sentinel.Store;

namespace Sentinel.Tests;

// E36: the L3 unattended envelope. The matrix pins every §3.1 gate;
// the integration test runs a scheduled-actor approval through the
// REAL dispatcher + executor + vault and proves only envelope-
// eligible files move.
public sealed class L3EnvelopeTests : IDisposable
{
    private readonly string _root;
    private bool _disposed;

    public L3EnvelopeTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "sentinel-e36-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch
        {
            // Best effort: temp cleanup never fails the test.
        }
    }

    private sealed class CapturingAudit : IActionAuditSink
    {
        public List<AuditDraft> Drafts { get; } = [];

        public bool TryAppend(AuditDraft draft, out long seq, out string error)
        {
            Drafts.Add(draft);
            seq = Drafts.Count;
            error = string.Empty;
            return true;
        }
    }

    private sealed class FixedLevels : IPermissionLevels
    {
        private readonly PermissionLevel _cleaner;

        public FixedLevels(PermissionLevel cleaner)
        {
            _cleaner = cleaner;
        }

        public PermissionLevel LevelFor(string module) =>
            module == "Cleaner" ? _cleaner : PermissionLevel.L0;
    }

    private static L3Candidate Candidate(
        string path = @"C:\t\a.tmp", RiskTier tier = RiskTier.Safe,
        DateTime? created = null, DateTime? modified = null,
        long size = 100, bool locked = false, bool placeholder = false)
    {
        var now = new DateTime(2026, 11, 4, 12, 0, 0, DateTimeKind.Utc);
        return new L3Candidate(path, tier,
            created ?? now - TimeSpan.FromHours(25),
            modified ?? now - TimeSpan.FromHours(25),
            size, locked, placeholder);
    }

    private static readonly DateTime FixedNow = new(2026, 11, 4, 12, 0, 0, DateTimeKind.Utc);

    private static L3Policy OpenPolicy() =>
        L3Policy.Defaults(enabled: true, PermissionLevel.L3);

    [Fact]
    public void RunRefused_WhenDisabled()
    {
        var policy = L3Policy.Defaults(enabled: false, PermissionLevel.L3);
        var selection = L3Envelope.SelectBatch([Candidate()], policy, FixedNow, crashEvidenceIn24h: false);

        Assert.NotNull(selection.RunRefusedReason);
        Assert.Contains("off", selection.RunRefusedReason);
        Assert.Empty(selection.Eligible);
        Assert.Single(selection.Impossible);
    }

    [Fact]
    public void RunRefused_WhenCleanerBelowL3()
    {
        var policy = L3Policy.Defaults(enabled: true, PermissionLevel.L2);
        var selection = L3Envelope.SelectBatch([Candidate()], policy, FixedNow, crashEvidenceIn24h: false);

        Assert.NotNull(selection.RunRefusedReason);
        Assert.Contains("L2", selection.RunRefusedReason);
        Assert.Empty(selection.Eligible);
    }

    [Fact]
    public void RunRefused_WhenCrashIn24h()
    {
        var selection = L3Envelope.SelectBatch([Candidate()], OpenPolicy(), FixedNow, crashEvidenceIn24h: true);

        Assert.NotNull(selection.RunRefusedReason);
        Assert.Contains("crash", selection.RunRefusedReason);
        Assert.Empty(selection.Eligible);
        Assert.Empty(selection.NeedsConfirm);
    }

    [Fact]
    public void RunAllowed_AllGatesPass()
    {
        var selection = L3Envelope.SelectBatch(
            [Candidate()], OpenPolicy(), FixedNow, crashEvidenceIn24h: false);

        Assert.Null(selection.RunRefusedReason);
        Assert.Single(selection.Eligible);
    }

    [Fact]
    public void Item_Review_NeedsConfirm_NeverAuto()
    {
        var selection = L3Envelope.SelectBatch(
            [Candidate(tier: RiskTier.Review)], OpenPolicy(), FixedNow, crashEvidenceIn24h: false);

        Assert.Empty(selection.Eligible);
        var verdict = Assert.Single(selection.NeedsConfirm);
        Assert.Contains("never auto-cleaned", verdict.Reason);
    }

    [Fact]
    public void Item_Never_Impossible()
    {
        var selection = L3Envelope.SelectBatch(
            [Candidate(tier: RiskTier.Never)], OpenPolicy(), FixedNow, crashEvidenceIn24h: false);

        Assert.Empty(selection.Eligible);
        Assert.Empty(selection.NeedsConfirm);
        var verdict = Assert.Single(selection.Impossible);
        Assert.Contains("Protected", verdict.Reason);
    }

    [Fact]
    public void Item_SafeYoung_Impossible()
    {
        var young = Candidate(created: FixedNow - TimeSpan.FromHours(1));
        var selection = L3Envelope.SelectBatch([young], OpenPolicy(), FixedNow, crashEvidenceIn24h: false);

        Assert.Empty(selection.Eligible);
        Assert.Contains("24 hours", selection.Impossible[0].Reason);
    }

    [Fact]
    public void Item_SafeRecentlyModified_Impossible()
    {
        var touched = Candidate(modified: FixedNow - TimeSpan.FromHours(1));
        var selection = L3Envelope.SelectBatch([touched], OpenPolicy(), FixedNow, crashEvidenceIn24h: false);

        Assert.Empty(selection.Eligible);
        Assert.Contains("Modified", selection.Impossible[0].Reason);
    }

    [Fact]
    public void Item_Boundary_Exactly24h_Auto()
    {
        var edge = Candidate(
            created: FixedNow - TimeSpan.FromHours(24),
            modified: FixedNow - TimeSpan.FromHours(24));
        var selection = L3Envelope.SelectBatch([edge], OpenPolicy(), FixedNow, crashEvidenceIn24h: false);

        Assert.Single(selection.Eligible);
    }

    [Fact]
    public void Item_Boundary_JustUnder24h_Impossible()
    {
        var edge = Candidate(
            created: FixedNow - TimeSpan.FromHours(24) + TimeSpan.FromSeconds(1),
            modified: FixedNow - TimeSpan.FromHours(25));
        var selection = L3Envelope.SelectBatch([edge], OpenPolicy(), FixedNow, crashEvidenceIn24h: false);

        Assert.Empty(selection.Eligible);
    }

    [Fact]
    public void Item_AgeUnknown_Impossible()
    {
        var unknown = Candidate() with { CreatedUtc = null };
        var selection = L3Envelope.SelectBatch([unknown], OpenPolicy(), FixedNow, crashEvidenceIn24h: false);

        Assert.Empty(selection.Eligible);
        Assert.Contains("Age unknown", selection.Impossible[0].Reason);
    }

    [Theory]
    [InlineData(true, false, "In use")]
    [InlineData(false, true, "placeholder")]
    public void Item_LockedOrPlaceholder_Impossible(bool locked, bool placeholder, string word)
    {
        var stuck = Candidate(locked: locked, placeholder: placeholder);
        var selection = L3Envelope.SelectBatch([stuck], OpenPolicy(), FixedNow, crashEvidenceIn24h: false);

        Assert.Empty(selection.Eligible);
        Assert.Contains(word, selection.Impossible[0].Reason);
    }

    [Fact]
    public void Caps_Items_OverflowCarries()
    {
        var many = Enumerable.Range(0, 5002)
            .Select(i => Candidate(path: $@"C:\t\f{i}.tmp", size: 10))
            .ToList();
        var selection = L3Envelope.SelectBatch(many, OpenPolicy(), FixedNow, crashEvidenceIn24h: false);

        Assert.Equal(5000, selection.Eligible.Count);
        Assert.Equal(2, selection.Impossible.Count);
        Assert.All(selection.Impossible, v => Assert.Contains("cap reached", v.Reason));
    }

    [Fact]
    public void Caps_Bytes_OverflowCarries()
    {
        var policy = OpenPolicy() with { MaxBytesPerRun = 100 };
        var selection = L3Envelope.SelectBatch(
            [Candidate(size: 60), Candidate(size: 60)], policy, FixedNow, crashEvidenceIn24h: false);

        Assert.Single(selection.Eligible);
        Assert.Single(selection.Impossible);
    }

    [Fact]
    public void Defaults_Pinned()
    {
        var policy = L3Policy.Defaults(enabled: true, PermissionLevel.L3);
        Assert.Equal(500L * 1024 * 1024, policy.MaxBytesPerRun);
        Assert.Equal(5000, policy.MaxItemsPerRun);
        Assert.Equal(TimeSpan.FromHours(24), policy.MinAge);
        Assert.Equal(TimeSpan.FromHours(24), policy.MinUnchanged);
    }

    [Fact]
    public void Settings_L3_DefaultOff_LegacySafe()
    {
        Assert.False(SentinelSettings.Defaults.L3AutoCleanEnabled);

        string path = Path.Combine(_root, "legacy.json");
        File.WriteAllText(path, """{"DefaultScanMode":"Balanced"}""");
        Assert.False(new SettingsStore(path).Load().L3AutoCleanEnabled);

        string on = Path.Combine(_root, "on.json");
        new SettingsStore(on).Save(SentinelSettings.Defaults with { L3AutoCleanEnabled = true });
        Assert.True(new SettingsStore(on).Load().L3AutoCleanEnabled);
    }

    [Fact]
    public void Stat_RealFile_ReturnsTierAndTimes()
    {
        string path = Path.Combine(_root, "stat.tmp");
        File.WriteAllText(path, "stat-me");
        var candidate = L3Envelope.Stat(path, new RiskClassifier(), DateTime.UtcNow);

        Assert.NotNull(candidate);
        Assert.Equal(RiskTier.Safe, candidate.Tier);
        Assert.Equal(7, candidate.SizeBytes);
        Assert.NotNull(candidate.CreatedUtc);
        Assert.False(candidate.Locked);
        Assert.False(candidate.Placeholder);
    }

    [Fact]
    public void Stat_MissingOrDir_ReturnsNull()
    {
        Assert.Null(L3Envelope.Stat(
            Path.Combine(_root, "nope.tmp"), new RiskClassifier(), DateTime.UtcNow));
        Assert.Null(L3Envelope.Stat(_root, new RiskClassifier(), DateTime.UtcNow));
    }

    [Fact]
    public void Stat_LockedFile_FlagsLocked()
    {
        string path = Path.Combine(_root, "statlock.tmp");
        File.WriteAllText(path, "x");
        using var hold = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        var candidate = L3Envelope.Stat(path, new RiskClassifier(), DateTime.UtcNow);

        Assert.NotNull(candidate);
        Assert.True(candidate.Locked);
    }

    [Fact]
    public async Task UnattendedRun_EligibleOnly_MovesToVault_ActorScheduled()
    {
        string old = Path.Combine(_root, "old.tmp");
        string fresh = Path.Combine(_root, "fresh.tmp");
        File.WriteAllText(old, "old-bytes");
        File.WriteAllText(fresh, "fresh-bytes");
        var past = DateTime.UtcNow - TimeSpan.FromHours(25);
        File.SetCreationTimeUtc(old, past);
        File.SetLastWriteTimeUtc(old, past);

        var classifier = new RiskClassifier();
        var now = DateTime.UtcNow;
        var candidates = new[] { old, fresh }
            .Select(p => L3Envelope.Stat(p, classifier, now))
            .Where(c => c is not null)
            .Select(c => c!)
            .ToList();
        Assert.Equal(2, candidates.Count);

        var selection = L3Envelope.SelectBatch(
            candidates, OpenPolicy(), now, crashEvidenceIn24h: false);
        Assert.Null(selection.RunRefusedReason);
        var eligible = Assert.Single(selection.Eligible);
        Assert.Equal(old, eligible.Candidate.Path);
        Assert.Single(selection.Impossible);

        // The unattended path: scheduled-actor approval through the
        // REAL dispatcher + executor + vault + audit.
        string vaultDir = Path.Combine(_root, "l3vault");
        using var vault = new VaultStore(Path.Combine(vaultDir, "vault.db"));
        var audit = new CapturingAudit();
        var dispatcher = new ActionDispatcher(audit, new FixedLevels(PermissionLevel.L3));
        Assert.True(dispatcher.RegisterExecutor("clean_items_to_vault", new CleanExecutor(
            () => vault, new DiskVaultFileIO(), Path.Combine(vaultDir, "files"),
            () => new RiskClassifier(), new StaticEvidenceSignerReader(), audit)));

        int n = 0;
        var approval = new ActionApproval(
            "clean_items_to_vault",
            selection.Eligible.Select(v =>
            {
                var info = new FileInfo(v.Candidate.Path);
                n++;
                return new ActionTarget($"l3:{n}", v.Candidate.Path, "file",
                    v.Candidate.Tier, info.Length, info.LastWriteTimeUtc.Ticks, null);
            }).ToList(),
            [_root], [], 1, DateTimeOffset.UtcNow,
            ActionActors.Scheduled, Guid.NewGuid().ToString("N"));

        var outcome = await dispatcher.DispatchAsync(approval, null, CancellationToken.None);

        Assert.Equal(BatchStatus.Completed, outcome.Status);
        Assert.False(File.Exists(old));
        Assert.True(File.Exists(fresh));
        Assert.Empty(vault.FindInterrupted());
        var row = vault.ListRestorable();
        var single = Assert.Single(row);
        Assert.Equal(ActionActors.Scheduled, single.Actor);
        Assert.All(audit.Drafts, d => Assert.Equal(ActionActors.Scheduled, d.Actor));
    }

    [Fact]
    public void UnattendedRun_CrashBlocks_NothingEligible()
    {
        string old = Path.Combine(_root, "crash-old.tmp");
        File.WriteAllText(old, "x");
        var past = DateTime.UtcNow - TimeSpan.FromHours(25);
        File.SetCreationTimeUtc(old, past);
        File.SetLastWriteTimeUtc(old, past);

        var candidate = L3Envelope.Stat(old, new RiskClassifier(), DateTime.UtcNow);
        Assert.NotNull(candidate);
        var selection = L3Envelope.SelectBatch(
            [candidate], OpenPolicy(), DateTime.UtcNow, crashEvidenceIn24h: true);

        Assert.NotNull(selection.RunRefusedReason);
        Assert.Empty(selection.Eligible);
        Assert.True(File.Exists(old));
    }
}
