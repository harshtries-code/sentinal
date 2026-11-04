using Sentinel.App.Services;
using Sentinel.Engine.Actions;
using Sentinel.Engine.Policy;
using Sentinel.Store;

namespace Sentinel.Tests;

// E35: the clean executor round trip + fault injection + undo. Real
// temp files, a real vault manifest, real moves — every failure path
// lands in a named state with the bytes accounted for.
public sealed class ActionRoundTripTests : IDisposable
{
    private readonly string _root;
    private bool _disposed;

    public ActionRoundTripTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "sentinel-e35-" + Guid.NewGuid().ToString("N"));
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

    private sealed class FaultVaultFileIO : IVaultFileIO
    {
        private readonly DiskVaultFileIO _real = new();

        public Func<string, Exception?>? MoveFault { get; set; }

        public bool CorruptAfterMove { get; set; }

        public Func<string, Exception?>? HashFault { get; set; }

        public void CreateDirectory(string path) => _real.CreateDirectory(path);

        public bool FileExists(string path) => _real.FileExists(path);

        public long GetSize(string path) => _real.GetSize(path);

        public void MoveFile(string source, string destination)
        {
            var fault = MoveFault?.Invoke(source);
            if (fault is not null)
            {
                throw fault;
            }

            _real.MoveFile(source, destination);
            if (CorruptAfterMove)
            {
                File.AppendAllText(destination, "CORRUPT!!");
            }
        }

        public string ComputeSha256(string path)
        {
            var fault = HashFault?.Invoke(path);
            if (fault is not null)
            {
                throw fault;
            }

            return _real.ComputeSha256(path);
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

    private string WriteFile(string name, string content)
    {
        string path = Path.Combine(_root, name);
        File.WriteAllText(path, content);
        return path;
    }

    private (VaultStore Vault, string Files) NewVault()
    {
        string dir = Path.Combine(_root, "v-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return (new VaultStore(Path.Combine(dir, "vault.db")), Path.Combine(dir, "files"));
    }

    private ActionApproval ApprovalFor(
        IEnumerable<string> paths, string? key = null, long generation = 1,
        RiskTier tier = RiskTier.Safe, string? signer = null, string kind = "file")
    {
        int n = 0;
        var targets = paths.Select(p =>
        {
            var info = new FileInfo(p);
            n++;
            return new ActionTarget($"f:{n}", p, kind, tier,
                info.Exists ? info.Length : 0,
                info.Exists ? info.LastWriteTimeUtc.Ticks : 0, signer);
        }).ToList();
        return new ActionApproval("clean_items_to_vault", targets, [_root], [],
            generation, DateTimeOffset.UtcNow, ActionActors.User,
            key ?? Guid.NewGuid().ToString("N"));
    }

    private static ActionTemplate CleanTemplate() =>
        ActionRegistry.Find("clean_items_to_vault")!;

    private CleanExecutor ExecutorFor(
        VaultStore vault, string files, IVaultFileIO io, CapturingAudit audit,
        Func<long?>? generation = null,
        Func<IReadOnlyList<string>>? orphans = null,
        Func<RiskClassifier>? classifier = null,
        Func<SentinelDb>? dbFactory = null) =>
        new(() => vault, io, files,
            classifier ?? (() => new RiskClassifier()),
            new StaticEvidenceSignerReader(), audit,
            dbFactory, generation, orphans);

    private static BatchExecutionRequest RequestFor(
        ActionApproval approval, IBrokerIdResolver? resolver = null,
        IProgress<ExecutionProgress>? progress = null) =>
        new(approval, CleanTemplate(), resolver, progress);

    [Fact]
    public async Task RoundTrip_SingleFile_MovesVerifiesAudits()
    {
        string path = WriteFile("rt-a.tmp", "round-trip-bytes");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        var executor = ExecutorFor(vault, vaultEnv.Files, new DiskVaultFileIO(), audit);
        var approval = ApprovalFor([path]);

        var result = await executor.ExecuteAsync(RequestFor(approval), CancellationToken.None);

        Assert.Equal(BatchStatus.Completed, result.Status);
        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Done, item.Status);
        Assert.True(item.UndoAvailable);
        Assert.NotNull(item.VaultRef);
        Assert.StartsWith("V-", item.VaultRef);

        // Source gone, vault copy byte-identical to the original.
        Assert.False(File.Exists(path));
        var row = vault.Get(item.VaultRef);
        Assert.NotNull(row);
        Assert.Equal(VaultStatus.Quarantined, row.Status);
        Assert.True(row.Verified);
        Assert.Equal(path, row.OriginalPath);
        string vaultPath = Path.Combine(vaultEnv.Files, row.VolumeLabel, row.VaultRelPath);
        Assert.Equal("round-trip-bytes", File.ReadAllText(vaultPath));
        Assert.Equal(16, vault.QueryRetainedBytes());

        // Batch tracked + per-item audit entry.
        var batch = vault.GetBatch(approval.IdempotencyKey);
        Assert.NotNull(batch);
        Assert.Equal("Completed", batch.Status);
        var entry = Assert.Single(audit.Drafts);
        Assert.Equal(["f:1"], entry.FindingIds);
        Assert.Equal("Vault:" + item.VaultRef, entry.BackupRef);
        Assert.Equal("Available:Vault:" + item.VaultRef, entry.UndoState);
        Assert.NotNull(entry.EvidenceHash);
    }

    [Fact]
    public async Task Undo_Restores_ByteIdentical()
    {
        string path = WriteFile("undo-a.tmp", "undo-bytes-123");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        var io = new DiskVaultFileIO();
        var executor = ExecutorFor(vault, vaultEnv.Files, io, audit);

        var result = await executor.ExecuteAsync(
            RequestFor(ApprovalFor([path])), CancellationToken.None);
        string vaultRef = result.Items[0].VaultRef!;

        var undo = new VaultUndoService(() => vault, io, vaultEnv.Files, audit);
        var restored = await undo.RestoreAsync([vaultRef], CancellationToken.None);

        var single = Assert.Single(restored);
        Assert.True(single.Restored);
        Assert.Equal(path, single.RestoredPath);
        Assert.Equal("undo-bytes-123", File.ReadAllText(path));
        Assert.Equal(VaultStatus.Restored, vault.Get(vaultRef)?.Status);
        Assert.Equal(0, vault.QueryRetainedBytes());
        Assert.Contains(audit.Drafts, d => d.UndoState == "Undone");
    }

    [Fact]
    public async Task Undo_Conflict_RestoresBeside_ExistingDataWins()
    {
        string path = WriteFile("conflict.tmp", "original-bytes");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        var io = new DiskVaultFileIO();

        var result = await ExecutorFor(vault, vaultEnv.Files, io, audit)
            .ExecuteAsync(RequestFor(ApprovalFor([path])), CancellationToken.None);
        string vaultRef = result.Items[0].VaultRef!;

        File.WriteAllText(path, "new-user-data");
        var undo = new VaultUndoService(() => vault, io, vaultEnv.Files, audit);
        var restored = await undo.RestoreAsync([vaultRef], CancellationToken.None);

        var single = Assert.Single(restored);
        Assert.True(single.Restored);
        Assert.NotEqual(path, single.RestoredPath);
        Assert.Contains("(restored 1)", single.RestoredPath);
        Assert.Equal("original-bytes", File.ReadAllText(single.RestoredPath!));
        Assert.Equal("new-user-data", File.ReadAllText(path));
    }

    [Fact]
    public async Task RevalidationRefusal_MidBatch_Partial()
    {
        string a = WriteFile("part-a.tmp", "aaa");
        string b = WriteFile("part-b.tmp", "bbb");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        var approval = ApprovalFor([a, b]);
        File.Delete(b);

        var result = await ExecutorFor(vault, vaultEnv.Files, new DiskVaultFileIO(), audit)
            .ExecuteAsync(RequestFor(approval), CancellationToken.None);

        Assert.Equal(BatchStatus.Partial, result.Status);
        Assert.Equal(ItemStatus.Done, result.Items[0].Status);
        Assert.Equal(ItemStatus.Refused, result.Items[1].Status);
        Assert.Contains("cannot be read", result.Items[1].Detail);
        Assert.Single(vault.ListRestorable());
        Assert.Equal(2, audit.Drafts.Count);
    }

    [Fact]
    public async Task Fault_MoveDenied_MapsToElevationRefused_SourceIntact()
    {
        string path = WriteFile("denied.tmp", "keep-me");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        var io = new FaultVaultFileIO
        {
            MoveFault = _ => new UnauthorizedAccessException("denied"),
        };

        var result = await ExecutorFor(vault, vaultEnv.Files, io, audit)
            .ExecuteAsync(RequestFor(ApprovalFor([path])), CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, result.Status);
        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Refused, item.Status);
        Assert.Contains("could not move", item.Detail);
        Assert.Equal("keep-me", File.ReadAllText(path));
        var residue = Assert.Single(vault.FindInterrupted());
        Assert.Contains("denied", residue.Detail);
    }

    [Fact]
    public async Task Fault_MoveIOException_Failed_SourceIntact()
    {
        string path = WriteFile("iofail.tmp", "keep-me-too");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        var io = new FaultVaultFileIO
        {
            MoveFault = _ => new IOException("disk hiccup"),
        };

        var result = await ExecutorFor(vault, vaultEnv.Files, io, audit)
            .ExecuteAsync(RequestFor(ApprovalFor([path])), CancellationToken.None);

        Assert.Equal(BatchStatus.Failed, result.Status);
        Assert.Contains("disk hiccup", result.Items[0].Detail);
        Assert.Equal("keep-me-too", File.ReadAllText(path));
        Assert.Single(vault.FindInterrupted());
    }

    [Fact]
    public async Task Fault_VerifyMismatch_MovesBackAndReports()
    {
        string path = WriteFile("corrupt.tmp", "pristine-bytes");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        var io = new FaultVaultFileIO { CorruptAfterMove = true };

        var result = await ExecutorFor(vault, vaultEnv.Files, io, audit)
            .ExecuteAsync(RequestFor(ApprovalFor([path])), CancellationToken.None);

        Assert.Equal(BatchStatus.Failed, result.Status);
        var item = Assert.Single(result.Items);
        Assert.Equal(ItemStatus.Failed, item.Status);
        Assert.Contains("failed verification", item.Detail);
        Assert.Contains("moved back", item.Detail);
        // The copy came back (corrupt!) with an explicit verify-first
        // warning — custody over quarantine purity.
        Assert.True(File.Exists(path));
        Assert.Contains("verify the file", item.Detail);
        Assert.Equal(VaultStatus.Superseded, vault.ListAll()[0].Status);
    }

    [Fact]
    public async Task Fault_AuditFailsAfterMove_RestoresSource_FailClosed()
    {
        string path = WriteFile("auditfail.tmp", "audit-me");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit { Fail = true };

        var result = await ExecutorFor(vault, vaultEnv.Files, new DiskVaultFileIO(), audit)
            .ExecuteAsync(RequestFor(ApprovalFor([path])), CancellationToken.None);

        Assert.Equal(BatchStatus.Failed, result.Status);
        Assert.Contains("restored to its place", result.Items[0].Detail);
        Assert.Equal("audit-me", File.ReadAllText(path));
        Assert.Equal(VaultStatus.Superseded, vault.ListAll()[0].Status);
        Assert.Equal(0, vault.QueryRetainedBytes());
    }

    [Fact]
    public async Task Cancel_PreCancelled_AllUntouched()
    {
        string a = WriteFile("pc-a.tmp", "a");
        string b = WriteFile("pc-b.tmp", "b");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var result = await ExecutorFor(vault, vaultEnv.Files, new DiskVaultFileIO(), audit)
            .ExecuteAsync(RequestFor(ApprovalFor([a, b])), cts.Token);

        Assert.Equal(BatchStatus.Cancelled, result.Status);
        Assert.All(result.Items, i => Assert.Equal(ItemStatus.Cancelled, i.Status));
        Assert.True(File.Exists(a));
        Assert.True(File.Exists(b));
        Assert.Empty(vault.ListAll());
    }

    [Fact]
    public async Task Cancel_MidRun_MovedStayUndoable_RestUntouched()
    {
        string a = WriteFile("c-a.tmp", "a");
        string b = WriteFile("c-b.tmp", "b");
        string c = WriteFile("c-c.tmp", "c");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        using var cts = new CancellationTokenSource();
        // Deterministic mid-run cancel: the fault hook fires during
        // item 2's move, so item 2 finishes and item 3 cancels.
        var io = new FaultVaultFileIO
        {
            MoveFault = src =>
            {
                if (src.EndsWith("c-b.tmp", StringComparison.OrdinalIgnoreCase))
                {
                    cts.Cancel();
                }

                return null;
            },
        };

        var result = await ExecutorFor(vault, vaultEnv.Files, io, audit)
            .ExecuteAsync(RequestFor(ApprovalFor([a, b, c])), cts.Token);

        Assert.Equal(BatchStatus.Cancelled, result.Status);
        Assert.Equal(ItemStatus.Done, result.Items[0].Status);
        Assert.Equal(ItemStatus.Done, result.Items[1].Status);
        Assert.True(result.Items[0].UndoAvailable);
        Assert.True(result.Items[1].UndoAvailable);
        Assert.Equal(ItemStatus.Cancelled, result.Items[2].Status);
        Assert.False(File.Exists(a));
        Assert.False(File.Exists(b));
        Assert.True(File.Exists(c));
    }

    [Fact]
    public async Task Idempotency_SameKey_RunsOnceAcrossExecutors()
    {
        string a = WriteFile("idem-a.tmp", "a");
        string b = WriteFile("idem-b.tmp", "b");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        string key = Guid.NewGuid().ToString("N");

        var first = await ExecutorFor(vault, vaultEnv.Files, new DiskVaultFileIO(), audit)
            .ExecuteAsync(RequestFor(ApprovalFor([a], key: key)), CancellationToken.None);
        Assert.Equal(BatchStatus.Completed, first.Status);

        // Same key, DIFFERENT files: must not run twice.
        var second = await ExecutorFor(vault, vaultEnv.Files, new DiskVaultFileIO(), audit)
            .ExecuteAsync(RequestFor(ApprovalFor([b], key: key)), CancellationToken.None);

        Assert.Equal(BatchStatus.Duplicate, second.Status);
        Assert.Empty(second.Items);
        Assert.True(File.Exists(b));
    }

    [Fact]
    public async Task Resolver_Mismatch_Refused()
    {
        string path = WriteFile("rebind.tmp", "x");
        string other = WriteFile("other.tmp", "y");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        // f:1 is approved for `path` but the broker now resolves it
        // to `other` — a rebinding attack or stale map.
        var resolver = new MapResolver(new Dictionary<string, string> { ["f:1"] = other });

        var result = await ExecutorFor(vault, vaultEnv.Files, new DiskVaultFileIO(), audit)
            .ExecuteAsync(RequestFor(ApprovalFor([path]), resolver), CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, result.Status);
        Assert.Contains("no longer resolves", result.Items[0].Detail);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task Resolver_Match_Proceeds()
    {
        string path = WriteFile("resolve.tmp", "x");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        var resolver = new MapResolver(new Dictionary<string, string> { ["f:1"] = path });

        var result = await ExecutorFor(vault, vaultEnv.Files, new DiskVaultFileIO(), audit)
            .ExecuteAsync(RequestFor(ApprovalFor([path]), resolver), CancellationToken.None);

        Assert.Equal(BatchStatus.Completed, result.Status);
    }

    [Fact]
    public async Task KindDir_Refused()
    {
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();

        var result = await ExecutorFor(vault, vaultEnv.Files, new DiskVaultFileIO(), audit)
            .ExecuteAsync(RequestFor(ApprovalFor([_root], kind: "dir")), CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, result.Status);
        Assert.Contains("Only files", result.Items[0].Detail);
    }

    [Fact]
    public async Task Generation_NewerScan_Refuses_AllItems()
    {
        string path = WriteFile("gen.tmp", "x");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();

        var result = await ExecutorFor(
                vault, vaultEnv.Files, new DiskVaultFileIO(), audit,
                generation: () => 10)
            .ExecuteAsync(RequestFor(ApprovalFor([path], generation: 9)), CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, result.Status);
        Assert.Contains("newer scan", result.Items[0].Detail);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task Generation_FromLiveDb_RefusesWhenDbAdvanced()
    {
        string path = WriteFile("gendb.tmp", "x");
        string dbPath = Path.Combine(_root, "gen.db");
        using (var seed = new SentinelDb(dbPath))
        {
            seed.Passport.BeginRun(_root, 10, "Balanced");
        }

        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();

        var result = await ExecutorFor(
                vault, vaultEnv.Files, new DiskVaultFileIO(), audit,
                dbFactory: () => new SentinelDb(dbPath))
            .ExecuteAsync(RequestFor(ApprovalFor([path], generation: 9)), CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, result.Status);
        Assert.Contains("newer scan", result.Items[0].Detail);
    }

    [Fact]
    public async Task Generation_EmptyDb_SkipsCheck_Proceeds()
    {
        string path = WriteFile("genempty.tmp", "x");
        string dbPath = Path.Combine(_root, "genempty.db");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();

        var result = await ExecutorFor(
                vault, vaultEnv.Files, new DiskVaultFileIO(), audit,
                dbFactory: () => new SentinelDb(dbPath))
            .ExecuteAsync(RequestFor(ApprovalFor([path], generation: 3)), CancellationToken.None);

        Assert.Equal(BatchStatus.Completed, result.Status);
    }

    [Fact]
    public async Task OrphanPredicate_FromLiveDb_ApprovedReviewProceeds()
    {
        string dir = Path.Combine(_root, "orphanapp");
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, "leftover.dll");
        File.WriteAllText(path, "orphan-bytes");
        string dbPath = Path.Combine(_root, "orphan.db");
        string normalized = Path.GetFullPath(dir)
            .TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant();
        using (var seed = new SentinelDb(dbPath))
        {
            seed.ReplaceOrphanDirs([(normalized, DateTime.UtcNow.Ticks, "quiet-200d")]);
        }

        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        // Program-roots rule would NEVER this file; the verified
        // orphan carve-out (from the live DB) makes it REVIEW.
        var classifier = new RiskClassifier(
            windows: @"C:\Windows", programFiles: _root, programFilesX86: @"C:\PFx86",
            programData: @"C:\PD", temp: @"C:\Temp", localAppData: @"C:\LAD",
            roamingAppData: @"C:\RAD", userDataRoots: [], neverList: []);

        var result = await ExecutorFor(
                vault, vaultEnv.Files, new DiskVaultFileIO(), audit,
                classifier: () => classifier,
                dbFactory: () => new SentinelDb(dbPath))
            .ExecuteAsync(
                RequestFor(ApprovalFor([path], tier: RiskTier.Review)),
                CancellationToken.None);

        Assert.Equal(BatchStatus.Completed, result.Status);
    }

    [Fact]
    public async Task SignerChanged_ViaProductionReader_Refused()
    {
        string path = WriteFile("signer.tmp", "unsigned-bytes");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();

        var result = await ExecutorFor(vault, vaultEnv.Files, new DiskVaultFileIO(), audit)
            .ExecuteAsync(
                RequestFor(ApprovalFor([path], signer: "CN=Somebody")),
                CancellationToken.None);

        Assert.Equal(BatchStatus.Refused, result.Status);
        Assert.Contains("signature changed", result.Items[0].Detail);
    }

    [Fact]
    public async Task Progress_ReportsPerItem()
    {
        string a = WriteFile("pr-a.tmp", "a");
        string b = WriteFile("pr-b.tmp", "b");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        var seen = new List<ExecutionProgress>();
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var progress = new Progress<ExecutionProgress>(p =>
        {
            lock (seen)
            {
                seen.Add(p);
                if (seen.Count == 2)
                {
                    gate.SetResult();
                }
            }
        });

        var result = await ExecutorFor(vault, vaultEnv.Files, new DiskVaultFileIO(), audit)
            .ExecuteAsync(RequestFor(ApprovalFor([a, b]), progress: progress), CancellationToken.None);

        Assert.Equal(BatchStatus.Completed, result.Status);
        await gate.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal([1, 2], seen.Select(p => p.Done).OrderBy(d => d).ToList());
        Assert.All(seen, p => Assert.Equal(2, p.Total));
    }

    [Fact]
    public async Task UnexpectedPerItemException_Continues_Partial()
    {
        string a = WriteFile("ux-a.tmp", "a");
        string b = WriteFile("ux-b.tmp", "b");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        var io = new FaultVaultFileIO
        {
            HashFault = p => p.EndsWith("ux-b.tmp", StringComparison.OrdinalIgnoreCase)
                ? new InvalidOperationException("hash exploded")
                : null,
        };

        var result = await ExecutorFor(vault, vaultEnv.Files, io, audit)
            .ExecuteAsync(RequestFor(ApprovalFor([a, b])), CancellationToken.None);

        Assert.Equal(BatchStatus.Partial, result.Status);
        Assert.Equal(ItemStatus.Done, result.Items[0].Status);
        Assert.Equal(ItemStatus.Failed, result.Items[1].Status);
        Assert.Contains("hash exploded", result.Items[1].Detail);
    }

    [Fact]
    public async Task TemplateMismatch_Backstop_Fails()
    {
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        var executor = ExecutorFor(vault, vaultEnv.Files, new DiskVaultFileIO(), audit);
        var defender = ActionRegistry.Find("defender_scan")!;
        var request = new BatchExecutionRequest(
            ApprovalFor([]) with { TemplateId = "defender_scan" },
            defender, null, null);

        var result = await executor.ExecuteAsync(request, CancellationToken.None);

        Assert.Equal(BatchStatus.Failed, result.Status);
        Assert.Contains("Wrong executor", result.Note);
    }

    [Fact]
    public async Task VaultManifestDown_FailsClosed_BeforeAnyMove()
    {
        string path = WriteFile("vaultdown.tmp", "x");
        var audit = new CapturingAudit();
        VaultStore Boom() => throw new IOException("vault disk gone");
        var executor = new CleanExecutor(
            Boom, new DiskVaultFileIO(), Path.Combine(_root, "vault"),
            () => new RiskClassifier(), new StaticEvidenceSignerReader(), audit);

        var result = await executor.ExecuteAsync(
            RequestFor(ApprovalFor([path])), CancellationToken.None);

        Assert.Equal(BatchStatus.Failed, result.Status);
        Assert.Contains("manifest is unavailable", result.Note);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task CollisionSafe_SameNameDifferentDirs()
    {
        string d1 = Path.Combine(_root, "same1");
        string d2 = Path.Combine(_root, "same2");
        Directory.CreateDirectory(d1);
        Directory.CreateDirectory(d2);
        string a = Path.Combine(d1, "dup.tmp");
        string b = Path.Combine(d2, "dup.tmp");
        File.WriteAllText(a, "first-bytes");
        File.WriteAllText(b, "second-bytes");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        var io = new DiskVaultFileIO();

        var result = await ExecutorFor(vault, vaultEnv.Files, io, audit)
            .ExecuteAsync(RequestFor(ApprovalFor([a, b])), CancellationToken.None);

        Assert.Equal(BatchStatus.Completed, result.Status);
        Assert.NotEqual(result.Items[0].VaultRef, result.Items[1].VaultRef);

        var undo = new VaultUndoService(() => vault, io, vaultEnv.Files, audit);
        var restored = await undo.RestoreAsync(
            [result.Items[0].VaultRef!, result.Items[1].VaultRef!], CancellationToken.None);

        Assert.All(restored, r => Assert.True(r.Restored));
        Assert.Equal("first-bytes", File.ReadAllText(a));
        Assert.Equal("second-bytes", File.ReadAllText(b));
    }

    [Fact]
    public async Task Undo_MissingVaultCopy_FailsHonestly()
    {
        string path = WriteFile("vmiss.tmp", "x");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        var io = new DiskVaultFileIO();

        var result = await ExecutorFor(vault, vaultEnv.Files, io, audit)
            .ExecuteAsync(RequestFor(ApprovalFor([path])), CancellationToken.None);
        string vaultRef = result.Items[0].VaultRef!;
        var row = vault.Get(vaultRef)!;
        File.Delete(Path.Combine(vaultEnv.Files, row.VolumeLabel, row.VaultRelPath));

        var undo = new VaultUndoService(() => vault, io, vaultEnv.Files, audit);
        var restored = await undo.RestoreAsync([vaultRef], CancellationToken.None);

        var single = Assert.Single(restored);
        Assert.False(single.Restored);
        Assert.Contains("missing", single.Detail);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task Undo_CorruptVaultCopy_Refuses_WritesNothing()
    {
        string path = WriteFile("vcorrupt.tmp", "good-bytes");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        var io = new DiskVaultFileIO();

        var result = await ExecutorFor(vault, vaultEnv.Files, io, audit)
            .ExecuteAsync(RequestFor(ApprovalFor([path])), CancellationToken.None);
        string vaultRef = result.Items[0].VaultRef!;
        var row = vault.Get(vaultRef)!;
        File.AppendAllText(
            Path.Combine(vaultEnv.Files, row.VolumeLabel, row.VaultRelPath), "CORRUPT");

        var undo = new VaultUndoService(() => vault, io, vaultEnv.Files, audit);
        var restored = await undo.RestoreAsync([vaultRef], CancellationToken.None);

        var single = Assert.Single(restored);
        Assert.False(single.Restored);
        Assert.Contains("damaged", single.Detail);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task Undo_ParentRecreated_NotesIt()
    {
        string dir = Path.Combine(_root, "gone-dir");
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, "f.tmp");
        File.WriteAllText(path, "parent-gone");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        var io = new DiskVaultFileIO();

        var result = await ExecutorFor(vault, vaultEnv.Files, io, audit)
            .ExecuteAsync(RequestFor(ApprovalFor([path])), CancellationToken.None);
        Directory.Delete(dir, recursive: true);

        var undo = new VaultUndoService(() => vault, io, vaultEnv.Files, audit);
        var restored = await undo.RestoreAsync([result.Items[0].VaultRef!], CancellationToken.None);

        var single = Assert.Single(restored);
        Assert.True(single.Restored);
        Assert.Contains("recreated", single.Detail);
        Assert.Equal("parent-gone", File.ReadAllText(path));
    }

    [Fact]
    public async Task Undo_AuditFailure_WarnsButKeepsRestore()
    {
        string path = WriteFile("uaufail.tmp", "x");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        var io = new DiskVaultFileIO();

        var result = await ExecutorFor(vault, vaultEnv.Files, io, audit)
            .ExecuteAsync(RequestFor(ApprovalFor([path])), CancellationToken.None);

        audit.Fail = true;
        var undo = new VaultUndoService(() => vault, io, vaultEnv.Files, audit);
        var restored = await undo.RestoreAsync([result.Items[0].VaultRef!], CancellationToken.None);

        var single = Assert.Single(restored);
        Assert.True(single.Restored);
        Assert.Contains("could not be audited", single.Detail);
        Assert.Equal("x", File.ReadAllText(path));
    }

    [Fact]
    public async Task Undo_Cancel_Midway_KeepsVaultCustody()
    {
        string a = WriteFile("uc-a.tmp", "a");
        string b = WriteFile("uc-b.tmp", "b");
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        var io = new DiskVaultFileIO();

        var result = await ExecutorFor(vault, vaultEnv.Files, io, audit)
            .ExecuteAsync(RequestFor(ApprovalFor([a, b])), CancellationToken.None);

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var undo = new VaultUndoService(() => vault, io, vaultEnv.Files, audit);
        var restored = await undo.RestoreAsync(
            [result.Items[0].VaultRef!, result.Items[1].VaultRef!], cts.Token);

        Assert.All(restored, r =>
        {
            Assert.False(r.Restored);
            Assert.Contains("Cancelled", r.Detail);
        });
        Assert.Equal(2, vault.ListRestorable().Count);
    }

    [Fact]
    public async Task Undo_NonQuarantined_Refused()
    {
        var vaultEnv = NewVault();
        using var vault = vaultEnv.Vault;
        var audit = new CapturingAudit();
        vault.RecordItem(new VaultItem("V-stuck", "B", Path.Combine(_root, "x.tmp"),
            "V-stuck__x.tmp", "C", 1, "sha", "2026-11-04T00:00:00Z",
            "clean_items_to_vault", "user", VaultStatus.InterruptedMove,
            false, null, null, null, "stuck"));

        var undo = new VaultUndoService(() => vault, new DiskVaultFileIO(), vaultEnv.Files, audit);
        var restored = await undo.RestoreAsync(["V-stuck", "V-nope"], CancellationToken.None);

        Assert.False(restored[0].Restored);
        Assert.Contains("Not restorable", restored[0].Detail);
        Assert.False(restored[1].Restored);
        Assert.Contains("No vault record", restored[1].Detail);
    }
}
