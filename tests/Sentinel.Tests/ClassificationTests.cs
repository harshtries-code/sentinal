using System.Text;
using Sentinel.App.ViewModels;
using Sentinel.Engine.Inventory;
using Sentinel.Engine.Policy;
using Sentinel.Store;

namespace Sentinel.Tests;

// P23: dead shortcuts, empty chains, keeper reasoning, per-app
// ownership. Temp DBs/dirs only; classifier roots are explicit so
// verdicts stay machine-independent.
public sealed class ClassificationTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 10, 30, 12, 0, 0, DateTimeKind.Utc);

    private readonly string _dir;

    public ClassificationTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "sentinel-p23-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(_dir, recursive: true);
        }
        catch
        {
        }
    }

    private SentinelDb NewDb([System.Runtime.CompilerServices.CallerMemberName] string name = "")
    {
        return new SentinelDb(Path.Combine(_dir, name + ".db"));
    }

    private static RiskClassifier TestClassifier(string[]? neverList = null) => new(
        @"C:\Win", @"C:\PF", @"C:\PF86", @"C:\PD", @"C:\Temp", @"C:\L", @"C:\R",
        [@"C:\U\Docs", @"C:\U\Desktop", @"C:\U\Downloads"],
        neverList ?? []);

    private static Fingerprint Fp(string path, int attrFlags = 0, int ageDays = 10) =>
        new(path, 1000, Now.AddDays(-ageDays).Ticks, null, 1, AttrFlags: attrFlags);

    // ---- .lnk local-target parser ----

    private static byte[] BuildLink(
        string? ansiPath, string? unicodePath = null,
        bool idList = false, bool linkInfo = true, bool clsid = true)
    {
        var header = new byte[76];
        BitConverter.GetBytes(0x4Cu).CopyTo(header, 0);
        if (clsid)
        {
            byte[] id =
            [
                0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
            ];
            id.CopyTo(header, 4);
        }

        uint flags = 0;
        if (idList)
        {
            flags |= 0x01;
        }

        if (linkInfo)
        {
            flags |= 0x02;
        }

        if (unicodePath is not null)
        {
            flags |= 0x80;
        }

        BitConverter.GetBytes(flags).CopyTo(header, 20);

        var body = new List<byte>(header);
        if (idList)
        {
            body.AddRange(BitConverter.GetBytes((ushort)4));
            body.AddRange([0xAA, 0xBB, 0xCC, 0xDD]);
        }

        if (linkInfo)
        {
            byte[] ansi = ansiPath is null ? [] : Encoding.Latin1.GetBytes(ansiPath + "\0");
            byte[] uni = unicodePath is null ? [] : Encoding.Unicode.GetBytes(unicodePath + "\0");
            int headSize = unicodePath is null ? 28 : 36;
            int ansiOff = ansi.Length == 0 ? 0 : headSize;
            int uniOff = uni.Length == 0 ? 0 : headSize + ansi.Length;
            int total = headSize + ansi.Length + uni.Length;
            var info = new List<byte>();
            info.AddRange(BitConverter.GetBytes((uint)total));
            info.AddRange(BitConverter.GetBytes((uint)headSize));
            info.AddRange(BitConverter.GetBytes(0x01u));
            info.AddRange(BitConverter.GetBytes(0u));
            info.AddRange(BitConverter.GetBytes((uint)ansiOff));
            info.AddRange(BitConverter.GetBytes(0u));
            info.AddRange(BitConverter.GetBytes(0u));
            if (unicodePath is not null)
            {
                info.AddRange(BitConverter.GetBytes((uint)uniOff));
                info.AddRange(BitConverter.GetBytes(0u));
            }

            info.AddRange(ansi);
            info.AddRange(uni);
            body.AddRange(info);
        }

        return body.ToArray();
    }

    [Fact]
    public void Shortcut_AnsiTarget_Parses()
    {
        string? target = ShortcutResolver.TryGetLocalTarget(
            BuildLink(@"C:\Apps\tool.exe"));
        Assert.Equal(@"C:\Apps\tool.exe", target);
    }

    [Fact]
    public void Shortcut_UnicodeTarget_Preferred()
    {
        string? target = ShortcutResolver.TryGetLocalTarget(
            BuildLink(@"C:\Apps\tool.exe", unicodePath: @"D:\Outils\outil.exe"));
        Assert.Equal(@"D:\Outils\outil.exe", target);
    }

    [Fact]
    public void Shortcut_WithIdList_SkipsToLinkInfo()
    {
        string? target = ShortcutResolver.TryGetLocalTarget(
            BuildLink(@"C:\Apps\tool.exe", idList: true));
        Assert.Equal(@"C:\Apps\tool.exe", target);
    }

    [Fact]
    public void Shortcut_WithoutLinkInfo_ReturnsNull()
    {
        Assert.Null(ShortcutResolver.TryGetLocalTarget(
            BuildLink(@"C:\Apps\tool.exe", linkInfo: false)));
    }

    [Fact]
    public void Shortcut_WrongClsid_ReturnsNull()
    {
        Assert.Null(ShortcutResolver.TryGetLocalTarget(
            BuildLink(@"C:\Apps\tool.exe", clsid: false)));
    }

    [Fact]
    public void Shortcut_UncTarget_ReturnsNull()
    {
        // A merely-offline network target must never read as dead.
        Assert.Null(ShortcutResolver.TryGetLocalTarget(
            BuildLink(@"\\server\share\tool.exe")));
    }

    [Fact]
    public void Shortcut_Truncated_ReturnsNull()
    {
        byte[] full = BuildLink(@"C:\Apps\tool.exe", idList: true);
        Assert.Null(ShortcutResolver.TryGetLocalTarget([]));
        Assert.Null(ShortcutResolver.TryGetLocalTarget(full.AsSpan(0, 10)));
        Assert.Null(ShortcutResolver.TryGetLocalTarget(full.AsSpan(0, 76)));
        Assert.Null(ShortcutResolver.TryGetLocalTarget(full.AsSpan(0, 80)));
        Assert.Null(ShortcutResolver.TryGetLocalTarget(full.AsSpan(0, full.Length - 2)));
    }

    // ---- Empty chains ----

    private static DirStat Stat(
        string dir, int files, int subdirs, int unverified = 0, int gen = 1) =>
        new(dir, files, subdirs, unverified, Now.Ticks, gen);

    [Fact]
    public void Chains_NestedChain_ReportsRootOnce_WithDepth()
    {
        var chains = EmptyChainFinder.FindChains([
            Stat(@"C:\A", 0, 1), Stat(@"C:\A\B", 0, 1), Stat(@"C:\A\B\C", 0, 0),
        ]);
        var only = Assert.Single(chains);
        Assert.Equal(@"C:\A", only.Dir);
        Assert.Equal(3, only.Depth);
    }

    [Fact]
    public void Chains_FileAnywhere_BreaksChain()
    {
        Assert.Empty(EmptyChainFinder.FindChains([
            Stat(@"C:\A", 0, 1), Stat(@"C:\A\B", 1, 0),
        ]));
    }

    [Fact]
    public void Chains_UnverifiedChild_Disqualifies()
    {
        // A dir holding only a symlink/exclusion is not empty.
        Assert.Empty(EmptyChainFinder.FindChains([
            Stat(@"C:\A", 0, 0, unverified: 1),
        ]));
        Assert.Empty(EmptyChainFinder.FindChains([
            Stat(@"C:\A", 0, 1), Stat(@"C:\A\B", 0, 0, unverified: 2),
        ]));
    }

    [Fact]
    public void Chains_MissingChildRow_DisqualifiesAncestors()
    {
        // A counted subdir with no census row was never verified.
        Assert.Empty(EmptyChainFinder.FindChains([
            Stat(@"C:\A", 0, 1),
        ]));
    }

    [Fact]
    public void Chains_Siblings_ReportedSeparately()
    {
        var chains = EmptyChainFinder.FindChains([
            Stat(@"C:\Live", 5, 2),
            Stat(@"C:\Live\A", 0, 1), Stat(@"C:\Live\A\B", 0, 0),
            Stat(@"C:\Live\C", 0, 0),
        ]);
        Assert.Equal(2, chains.Count);
        Assert.Contains(chains, c => c.Dir == @"C:\Live\A" && c.Depth == 2);
        Assert.Contains(chains, c => c.Dir == @"C:\Live\C" && c.Depth == 1);
    }

    [Fact]
    public void LiveSet_Vetoes_StaleChains()
    {
        var live = EmptyChainFinder.EmptyChainLiveSet.FromParents(
            [@"C:\A\B", @"C:\Other"]);
        Assert.True(live.HasFilesAtOrUnder(@"C:\A\B"));
        Assert.True(live.HasFilesAtOrUnder(@"C:\A"));
        Assert.True(live.HasFilesAtOrUnder(@"c:\a"));
        Assert.False(live.HasFilesAtOrUnder(@"C:\Elsewhere"));
        // Prefix text without a separator boundary is not "under".
        Assert.False(live.HasFilesAtOrUnder(@"C:\A\Bx"));
    }

    // ---- Dead-shortcut classification ----

    [Fact]
    public void DeadShortcut_UnderProgramRoots_IsReview()
    {
        var c = TestClassifier();
        foreach (string path in new[]
        {
            @"C:\PF\OldApp\app.lnk",
            @"C:\PD\Microsoft\Windows\Start Menu\old.lnk",
            @"C:\U\Desktop\old.lnk",
            @"C:\U\Docs\old.lnk",
        })
        {
            var got = c.Classify(Fp(path, FingerprintAttrs.DeadShortcut), Now);
            Assert.Equal(RiskTier.Review, got.Tier);
            Assert.Contains("R-deadshortcut", got.RuleIds);
        }
    }

    [Fact]
    public void DeadShortcut_NeverList_StillWins()
    {
        var c = TestClassifier([@"C:\PF\OldApp"]);
        var got = c.Classify(
            Fp(@"C:\PF\OldApp\app.lnk", FingerprintAttrs.DeadShortcut), Now);
        Assert.Equal(RiskTier.Never, got.Tier);
        Assert.Contains("N-neverlist", got.RuleIds);
    }

    [Fact]
    public void DeadShortcut_NeedsFlag_AndExtension()
    {
        var c = TestClassifier();
        // Same path, no verified-dead flag: unknown location stays NEVER.
        var unflagged = c.Classify(Fp(@"C:\Work\app.lnk"), Now);
        Assert.Equal(RiskTier.Never, unflagged.Tier);
        // Flag on a non-shortcut: ignored.
        var wrongExt = c.Classify(
            Fp(@"C:\Work\app.exe", FingerprintAttrs.DeadShortcut), Now);
        Assert.Equal(RiskTier.Never, wrongExt.Tier);
    }

    // ---- Keeper reasoning ----

    private static Fingerprint Member(
        string path, string hash, long mtime, string? tier = null) =>
        new(path, 1000, mtime, hash, 1, Tier: tier);

    [Fact]
    public void Keeper_PrefersAppRoot_BeatsUser_BeatsDownloads_BeatsBin()
    {
        var members = new List<Fingerprint>
        {
            Member(@"C:\$Recycle.Bin\S-1\a.dll", "H", 300, "REVIEW"),
            Member(@"C:\U\Downloads\a.dll", "H", 250),
            Member(@"C:\U\Docs\a.dll", "H", 200),
            Member(@"C:\PF\Tool\a.dll", "H", 100, "NEVER"),
        };
        var entries = new List<UninstallEntry>
        {
            new("Tool", @"C:\PF\Tool", null, null),
        };
        var got = DuplicateComparer.Compare(
            "H", 1000, members, [@"C:\PF"], [@"C:\U\Downloads"], entries);
        var order = got.CopiesOrdered.Select(c => c.Path).ToList();
        Assert.Equal(
            [
                @"C:\PF\Tool\a.dll",
                @"C:\U\Docs\a.dll",
                @"C:\U\Downloads\a.dll",
                @"C:\$Recycle.Bin\S-1\a.dll",
            ], order);
        Assert.True(got.CopiesOrdered[0].IsKeeper);
        Assert.All(got.CopiesOrdered.Skip(1), c => Assert.False(c.IsKeeper));
        // Identical bytes never become a deletion pick: no copy is
        // ever labelled safe-to-delete (bin copies name the review).
        Assert.All(got.CopiesOrdered, c => Assert.All(c.Reasons, r =>
            Assert.DoesNotContain("delete", r, StringComparison.OrdinalIgnoreCase)));
        Assert.Contains(
            got.CopiesOrdered[0].Reasons, r => r.Contains("Program Files") || r.Contains("PF"));
        Assert.Contains(
            got.CopiesOrdered[0].Reasons, r => r.Contains("Claimed by Tool"));
        Assert.Contains(
            got.CopiesOrdered[3].Reasons, r => r.Contains("Recycle Bin"));
    }

    [Fact]
    public void Keeper_NamesNewest_AndProtection()
    {
        var members = new List<Fingerprint>
        {
            Member(@"C:\Work\a.dll", "H", 100, "NEVER"),
            Member(@"C:\Work\sub\a.dll", "H", 200, "SAFE"),
        };
        var got = DuplicateComparer.Compare(
            "H", 1000, members, [@"C:\PF"], [@"C:\U\Downloads"], []);
        // Same rank: newest wins.
        Assert.Equal(@"C:\Work\sub\a.dll", got.CopiesOrdered[0].Path);
        Assert.Contains(got.CopiesOrdered[0].Reasons, r => r.Contains("Newest copy"));
        Assert.Contains(
            got.CopiesOrdered[0].Reasons, r => r.Contains("No installed app claims"));
        Assert.Contains(
            got.CopiesOrdered[1].Reasons, r => r.Contains("Protected (Never Touch)"));
    }

    [Fact]
    public void Keeper_EmptyMembers_ReturnsEmpty()
    {
        var got = DuplicateComparer.Compare("H", 0, [], [@"C:\PF"], null, []);
        Assert.Empty(got.CopiesOrdered);
    }

    [Fact]
    public void Finder_LastRoots_RankBelowUnlisted_AboveBin()
    {
        var files = new List<Fingerprint>
        {
            Member(@"C:\$Recycle.Bin\S-1\a.dll", "H", 300),
            Member(@"C:\U\Downloads\a.dll", "H", 250),
            Member(@"C:\U\Docs\a.dll", "H", 200),
        };
        var groups = DuplicateFinder.FindByHash(files, [@"C:\PF"], 0, [@"C:\U\Downloads"]);
        var only = Assert.Single(groups);
        Assert.Equal(
            [@"C:\U\Docs\a.dll", @"C:\U\Downloads\a.dll", @"C:\$Recycle.Bin\S-1\a.dll"],
            only.CopiesOrdered);
    }

    [Fact]
    public void Finder_WithoutLastRoots_KeepsLegacyOrder()
    {
        var files = new List<Fingerprint>
        {
            Member(@"C:\U\Downloads\a.dll", "H", 250),
            Member(@"C:\U\Docs\a.dll", "H", 200),
        };
        var groups = DuplicateFinder.FindByHash(files, [@"C:\PF"], 0);
        var only = Assert.Single(groups);
        // Same rank: newest first (pre-P23 tiebreak, unchanged).
        Assert.Equal([@"C:\U\Downloads\a.dll", @"C:\U\Docs\a.dll"], only.CopiesOrdered);
    }

    // ---- Per-app ownership ----

    [Fact]
    public void Ownership_MergesSameApp_LocationsOrdered()
    {
        var groups = new List<AppGroup>
        {
            new("Tool", @"C:\R\Tool", 3, 30, true),
            new("Tool", @"C:\PF\Tool", 10, 1000, true),
            new("Tool", @"C:\L\Tool", 5, 100, true),
        };
        var roots = new List<(string, AppLocationKind)>
        {
            (@"C:\PF", AppLocationKind.Install),
            (@"C:\L", AppLocationKind.LocalData),
            (@"C:\R", AppLocationKind.RoamingData),
        };
        var owned = AppOwnershipMerger.Merge(groups, roots);
        var only = Assert.Single(owned);
        Assert.Equal("Tool", only.AppName);
        Assert.True(only.Known);
        Assert.Equal(18, only.TotalFiles);
        Assert.Equal(1130, only.TotalBytes);
        Assert.Equal(
            [AppLocationKind.Install, AppLocationKind.LocalData, AppLocationKind.RoamingData],
            only.Locations.Select(l => l.Kind).ToList());
        Assert.All(
            only.Locations,
            l => Assert.False(string.IsNullOrWhiteSpace(AppOwnershipMerger.GuidanceFor(l.Kind))));
    }

    [Fact]
    public void Ownership_UnknownFolders_StaySeparate()
    {
        var groups = new List<AppGroup>
        {
            new("Unknown", @"C:\PF\MysteryA", 1, 10, false),
            new("Unknown", @"C:\L\MysteryB", 2, 20, false),
        };
        var owned = AppOwnershipMerger.Merge(
            groups, [( @"C:\PF", AppLocationKind.Install)]);
        Assert.Equal(2, owned.Count);
        Assert.All(owned, o => Assert.False(o.Known));
        Assert.All(owned, o => Assert.Single(o.Locations));
        Assert.Contains("Unclaimed", AppOwnershipMerger.GuidanceFor(AppLocationKind.Unknown));
    }

    // ---- Directory census + dead-link store ----

    [Fact]
    public void DirStats_ReplaceIsScopeIsolated()
    {
        using var db = NewDb();
        string a = Path.Combine(_dir, "scopeA");
        string b = Path.Combine(_dir, "scopeB");
        db.ReplaceDirStats(a, [new DirStat(a, 1, 0, 0, 5, 1)], 1);
        db.ReplaceDirStats(b, [new DirStat(b, 2, 0, 0, 6, 1)], 1);
        Assert.Equal(2, db.QueryDirStats().Count);
        // Replacing A (now empty) keeps B's rows.
        db.ReplaceDirStats(a, [], 2);
        var rows = db.QueryDirStats();
        var only = Assert.Single(rows);
        Assert.Equal(b, only.Dir);
        Assert.Equal(2, only.DirectFiles);
    }

    [Fact]
    public void DeadLinks_Roundtrip_AndPurgeWithFingerprint()
    {
        using var db = NewDb();
        string root = Path.Combine(_dir, "links");
        string lnk = Path.Combine(root, "old.lnk");
        db.UpsertDeadLink(lnk, @"C:\gone\target.exe");
        Assert.Equal(@"C:\gone\target.exe", db.QueryDeadLink(lnk));
        db.DeleteDeadLink(lnk);
        Assert.Null(db.QueryDeadLink(lnk));

        db.UpsertFingerprint(lnk, 500, Now.Ticks, null, 1);
        db.UpsertDeadLink(lnk, @"C:\gone\target.exe");
        db.DeleteFingerprintsNotSeenIn(root, 2, []);
        Assert.Null(db.GetFingerprint(lnk));
        Assert.Null(db.QueryDeadLink(lnk));
    }

    [Fact]
    public void DuplicateMembers_ReturnsPerCopyFacts()
    {
        using var db = NewDb();
        db.UpsertFingerprint(@"C:\X\a.dll", 100, 11, "H", 1);
        db.UpsertFingerprint(@"C:\Y\a.dll", 100, 22, "H", 1);
        db.UpsertFingerprint(@"C:\Z\b.dll", 100, 33, "OTHER", 1);
        var members = db.QueryDuplicateMembers("H");
        Assert.Equal(2, members.Count);
        Assert.Contains(members, m => m.MTimeUtcTicks == 11);
        Assert.Contains(members, m => m.MTimeUtcTicks == 22);
    }

    // ---- Scanner integration ----

    [Fact]
    public async Task Scan_WritesCensus_FlagsDeadShortcut_AndFindsChain()
    {
        string root = Path.Combine(_dir, "scan");
        string tag = Guid.NewGuid().ToString("N");
        string chainA = Path.Combine(root, $"chainA-{tag}");
        string chainB = Path.Combine(chainA, $"chainB-{tag}");
        Directory.CreateDirectory(chainB);
        string live = Path.Combine(root, "live.txt");
        File.WriteAllText(live, "here");
        string dead = Path.Combine(root, "dead.lnk");
        string deadTarget = Path.Combine(root, "gone", "missing.exe");
        File.WriteAllBytes(dead, BuildLink(deadTarget));
        string alive = Path.Combine(root, "alive.lnk");
        File.WriteAllBytes(alive, BuildLink(live));
        DateTime old = DateTime.UtcNow.AddDays(-200);
        Directory.SetLastWriteTimeUtc(chainB, old);
        Directory.SetLastWriteTimeUtc(chainA, old);

        using var db = NewDb();
        var scanner = new DiskInventoryScanner(db)
        {
            Classifier = TestClassifier(),
            ClassifyUtcNow = DateTime.UtcNow,
        };
        var result = await scanner.ScanAsync(root, 1);
        Assert.Empty(result.Gaps);

        var deadRow = db.GetFingerprint(dead);
        Assert.NotNull(deadRow);
        Assert.True((deadRow.AttrFlags & FingerprintAttrs.DeadShortcut) != 0);
        Assert.Equal(deadTarget, db.QueryDeadLink(dead));
        Assert.Equal("REVIEW", deadRow.Tier);
        var aliveRow = db.GetFingerprint(alive);
        Assert.NotNull(aliveRow);
        Assert.True((aliveRow.AttrFlags & FingerprintAttrs.DeadShortcut) == 0);
        Assert.Null(db.QueryDeadLink(alive));

        var stats = db.QueryDirStats().ToDictionary(s => s.Dir, StringComparer.OrdinalIgnoreCase);
        Assert.True(stats.ContainsKey(chainA));
        Assert.Equal(0, stats[chainA].DirectFiles);
        Assert.Equal(1, stats[chainA].DirectSubdirs);
        Assert.Equal(0, stats[chainA].DirectUnverified);
        Assert.True(stats.ContainsKey(chainB));

        new InventoryClassifier(db, []).EnsureClassified(DateTime.UtcNow, CancellationToken.None);
        var verdicts = db.QueryOrphanDirs(100, 0, out _);
        Assert.Contains(verdicts, v =>
            v.Dir.StartsWith(chainA.ToUpperInvariant(), StringComparison.Ordinal)
            && v.Signals.Contains("EmptyChain")
            && v.Signals.Contains("Depth2"));
    }

    [Fact]
    public void DeltaAddedFile_VetoesStaleChain()
    {
        using var db = NewDb();
        string root = Path.Combine(_dir, "stale");
        string dirA = Path.Combine(root, "ghostA");
        string dirB = Path.Combine(dirA, "ghostB");
        long old = DateTime.UtcNow.AddDays(-200).Ticks;
        db.ReplaceDirStats(root, [
            new DirStat(dirA, 0, 1, 0, old, 1),
            new DirStat(dirB, 0, 0, 0, old, 1),
        ], 1);
        // A delta adds a file under the "empty" chain without
        // rewriting the census: live files veto the stale chain.
        db.UpsertFingerprint(
            Path.Combine(dirB, "new.txt"), 10, DateTime.UtcNow.Ticks, null, 2);

        new InventoryClassifier(db, []).EnsureClassified(DateTime.UtcNow, CancellationToken.None);
        var verdicts = db.QueryOrphanDirs(100, 0, out _);
        Assert.DoesNotContain(verdicts, v =>
            v.Dir.StartsWith(dirA.ToUpperInvariant(), StringComparison.Ordinal));
    }

    // ---- Storage page wiring ----

    private string VmDbPath(string name) => Path.Combine(_dir, name + ".db");

    [Fact]
    public void Vm_DuplicatesChip_ShowsKeeperFirst_WithReasons()
    {
        string path = VmDbPath("dupes");
        string pf = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "sentinel-p23-" + Guid.NewGuid().ToString("N"), "lib.dll");
        string tmp = Path.Combine(_dir, "lib.dll");
        using (var db = new SentinelDb(path))
        {
            // Temp copy is NEWER: rank still beats mtime.
            db.UpsertFingerprint(pf, 1000, Now.AddDays(-9).Ticks, "DUP23", 1);
            db.UpsertFingerprint(tmp, 1000, Now.AddDays(-1).Ticks, "DUP23", 1);
        }

        var vm = new CleanerViewModel(() => new SentinelDb(path), () => []);
        vm.Refresh();
        vm.SelectedChip = "Duplicates";
        var row = Assert.Single(vm.VisibleRows);
        Assert.Equal(StorageRowKind.Duplicate, row.Kind);
        Assert.Equal(2, row.Detail.ExtraPaths.Count);
        Assert.StartsWith("Suggested keeper", row.Detail.ExtraPaths[0]);
        Assert.Contains(pf, row.Detail.ExtraPaths[0]);
        Assert.Contains("Program Files", row.Detail.ExtraPaths[0]);
        Assert.StartsWith("Spare copy", row.Detail.ExtraPaths[1]);
        Assert.Contains("Suggested keeper:", row.Detail.KnowLine);
    }

    [Fact]
    public void Vm_AppsChip_ShowsUnknownLocations_WithGuidance()
    {
        string path = VmDbPath("apps");
        string local = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "sentinel-p23-" + Guid.NewGuid().ToString("N"), "g.exe");
        string pf = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "sentinel-p23-" + Guid.NewGuid().ToString("N"), "f.exe");
        using (var db = new SentinelDb(path))
        {
            db.UpsertFingerprint(local, 100, Now.Ticks, null, 1);
            db.UpsertFingerprint(pf, 200, Now.Ticks, null, 1);
        }

        var vm = new CleanerViewModel(() => new SentinelDb(path), () => []);
        vm.Refresh();
        vm.SelectedChip = "Apps";
        Assert.Equal(2, vm.VisibleRows.Count);
        Assert.All(vm.VisibleRows, r =>
        {
            Assert.Equal(StorageRowKind.App, r.Kind);
            Assert.Contains("Unknown app", r.Classification);
            Assert.Contains("Unknown owner", r.Detail.TierLine);
            Assert.Contains("1 location", r.Detail.KnowLine);
            var line = Assert.Single(r.Detail.ExtraPaths);
            // Kind label + kind guidance (Install vs Local data).
            Assert.True(
                line.Contains("Install — ") || line.Contains("Local data — "),
                "Location line names its kind: " + line);
        });
    }

    [Fact]
    public void Vm_DeadShortcutRow_NamesMissingTarget()
    {
        string path = VmDbPath("deadlnk");
        string lnk = Path.Combine(_dir, "old.lnk");
        string target = Path.Combine(_dir, "gone", "target.exe");
        using (var db = new SentinelDb(path))
        {
            db.UpsertFingerprint(lnk, 500, Now.Ticks, null, 1, FingerprintAttrs.DeadShortcut);
            db.UpsertDeadLink(lnk, target);
        }

        var vm = new CleanerViewModel(() => new SentinelDb(path), () => []);
        vm.Refresh();
        vm.SelectedChip = "Review";
        var row = Assert.Single(vm.VisibleRows, r => r.Detail.FullPath == lnk);
        Assert.Equal("REVIEW", row.Tier);
        Assert.Contains(target, row.Detail.KnowLine);
        Assert.Contains("which is gone", row.Detail.KnowLine);
    }

    [Fact]
    public void Protections_Pin_Browser_Livedb_Gamesave_Rules()
    {
        var c = TestClassifier();
        var cases = new (string Path, string Rule)[]
        {
            (@"C:\L\Google\Chrome\User Data\Default\History", "N-browserdata"),
            (@"C:\R\Mozilla\Firefox\Profiles\abc\places.sqlite", "N-browserdata"),
            (@"C:\L\Tool\store.sqlite", "N-livedb"),
            (@"C:\Work\mail.pst", "N-livedb"),
            (@"C:\Work\shooter\save.sav", "N-gamesave"),
            (@"C:\L\GameStudio\shooter\savegame.dat", "N-gamesave"),
        };
        foreach (var (path, rule) in cases)
        {
            var got = c.Classify(Fp(path), Now);
            Assert.Equal(RiskTier.Never, got.Tier);
            Assert.Contains(rule, got.RuleIds);
        }
    }

    [Fact]
    public void SystemFileNote_NamesManagedFile_OrNullWhenAbsent()
    {
        string present = Path.Combine(_dir, "pagefile.sys");
        File.WriteAllBytes(present, new byte[100]);
        string? note = CleanerViewModel.DescribeSystemFile(present);
        Assert.NotNull(note);
        Assert.Contains("managed by Windows", note);
        Assert.Null(CleanerViewModel.DescribeSystemFile(
            Path.Combine(_dir, "hiberfil.sys")));
    }

    [Fact]
    public void Vm_OrphansChip_ShowsEmptyChainSignal()
    {
        string path = VmDbPath("chains");
        string dirA = Path.Combine(_dir, "ghostA");
        string dirB = Path.Combine(dirA, "ghostB");
        long old = DateTime.UtcNow.AddDays(-200).Ticks;
        using (var db = new SentinelDb(path))
        {
            db.ReplaceDirStats(_dir, [
                new DirStat(dirA, 0, 1, 0, old, 1),
                new DirStat(dirB, 0, 0, 0, old, 1),
            ], 1);
        }

        var vm = new CleanerViewModel(() => new SentinelDb(path), () => []);
        vm.Refresh();
        vm.SelectedChip = "Orphans";
        var row = Assert.Single(vm.VisibleRows);
        Assert.Equal(StorageRowKind.Orphan, row.Kind);
        Assert.Contains("EmptyChain", row.Detail.KnowLine);
        Assert.Contains("Depth2", row.Detail.KnowLine);
    }
}
