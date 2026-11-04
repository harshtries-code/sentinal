using Sentinel.Engine.Policy;
using Sentinel.Store;

namespace Sentinel.Tests;

// Layer 2 classification tests (05 §2, 04 Phase 2). The corpus
// test is the 04 false-positive gate: ZERO deletion
// recommendations (SAFE or REVIEW) across game-like, signed,
// live-data, and user files. Any hit = stop the line.
public sealed class PolicyTests
{
    private static readonly DateTime Now = new(2026, 10, 30, 12, 0, 0, DateTimeKind.Utc);

    private static RiskClassifier TestClassifier(string[]? neverList = null) => new(
        @"C:\Win", @"C:\PF", @"C:\PF86", @"C:\PD", @"C:\Temp", @"C:\L", @"C:\R",
        [@"C:\U\Docs", @"C:\U\Pics", @"C:\U\Music", @"C:\U\Desktop", @"C:\U\Downloads", @"C:\U\Videos", @"C:\U\OneDrive"],
        neverList ?? []);

    private static Fingerprint Fp(string path, long size = 1000, int ageDays = 10) =>
        new(path, size, Now.AddDays(-ageDays).Ticks, null, 1);

    [Fact]
    public void SafeRules_Classify_KnownRegenerable()
    {
        var c = TestClassifier();
        var cases = new (string Path, int Age, string Rule)[]
        {
            (@"C:\Temp\junk.tmp", 1, "S-temp"),
            (@"C:\Win\Temp\wd.log", 1, "S-wintemp"),
            (@"C:\Win\SoftwareDistribution\Download\kb.bin", 10, "S-updateleftovers"),
            (@"C:\Win\Prefetch\APP.EXE-123.pf", 5, "S-prefetch"),
            (@"C:\L\Microsoft\Windows\Explorer\thumbcache_256.db", 5, "S-thumbcache"),
            (@"C:\L\Microsoft\Windows\Explorer\IconCache.db", 5, "S-thumbcache"),
            (@"C:\L\NVIDIA\DXCache\shader.bin", 5, "S-shadercache"),
            (@"C:\L\Google\Chrome\User Data\Default\Cache\data_1", 1, "S-browsercache"),
            (@"C:\L\Google\Chrome\User Data\Default\Code Cache\js\index", 1, "S-browsercache"),
            (@"C:\Win\Logs\setup.log", 40, "S-setuplog"),
            (@"C:\Win\MEMORY.DMP", 60, "S-olddump"),
        };

        foreach (var (path, age, rule) in cases)
        {
            var got = c.Classify(Fp(path, ageDays: age), Now);
            Assert.True(got.Tier == RiskTier.Safe, $"{path} -> {got.Tier} ({string.Join(",", got.RuleIds)})");
            Assert.Contains(rule, got.RuleIds);
            Assert.NotEmpty(got.Reasons);
        }
    }

    [Fact]
    public void SafeCaches_Carry_RegrowthNotes()
    {
        var c = TestClassifier();
        var got = c.Classify(Fp(@"C:\L\Microsoft\Windows\Explorer\thumbcache_256.db"), Now);
        Assert.Equal(RiskTier.Safe, got.Tier);
        Assert.NotNull(got.ExpectedRegrowth);

        var temp = c.Classify(Fp(@"C:\Temp\a.tmp"), Now);
        Assert.Null(temp.ExpectedRegrowth);
    }

    [Fact]
    public void ReviewRules_Need_HumanJudgement()
    {
        var c = TestClassifier();

        var dl = c.Classify(Fp(@"C:\U\Downloads\setup.exe", ageDays: 120), Now);
        Assert.Equal(RiskTier.Review, dl.Tier);
        Assert.Contains("R-olddownload", dl.RuleIds);

        var big = c.Classify(Fp(@"C:\Work\archive.iso", size: 2L * 1024 * 1024 * 1024, ageDays: 200), Now);
        Assert.Equal(RiskTier.Review, big.Tier);
        Assert.Contains("R-largeold", big.RuleIds);

        var bin = c.Classify(Fp(@"C:\$Recycle.Bin\S-1\old.doc"), Now);
        Assert.Equal(RiskTier.Review, bin.Tier);
        Assert.Contains("R-recycle", bin.RuleIds);
    }

    [Fact]
    public void AgeGates_Fall_Safe()
    {
        var c = TestClassifier();
        // Young update leftovers / logs / dumps / downloads stay NEVER.
        Assert.Equal(RiskTier.Never, c.Classify(Fp(@"C:\Win\SoftwareDistribution\Download\kb.bin", ageDays: 2), Now).Tier);
        Assert.Equal(RiskTier.Never, c.Classify(Fp(@"C:\Win\Logs\setup.log", ageDays: 2), Now).Tier);
        Assert.Equal(RiskTier.Never, c.Classify(Fp(@"C:\Win\MEMORY.DMP", ageDays: 2), Now).Tier);
        Assert.Equal(RiskTier.Never, c.Classify(Fp(@"C:\U\Downloads\fresh.exe", ageDays: 5), Now).Tier);
        Assert.Equal(RiskTier.Never, c.Classify(Fp(@"C:\Work\archive.iso", size: 2L * 1024 * 1024 * 1024, ageDays: 5), Now).Tier);
    }

    [Fact]
    public void FalsePositiveCorpus_Yields_ZeroDeletionRecommendations()
    {
        var c = TestClassifier(["C:\\Keep"]);
        string[] corpus =
        [
            // Game files: the owner's canonical false-positive case.
            @"C:\PF\Game\game.exe",
            @"C:\PF\Game\data\textures.pak",
            @"C:\U\Docs\My Games\shooter\save.sav",
            @"C:\U\Docs\My Games\shooter\settings.ini",
            @"C:\L\GameStudio\shooter\savegame.dat",
            // Signed OS / driver files.
            @"C:\Win\System32\kernel32.dll",
            @"C:\Win\System32\drivers\disk.sys",
            @"C:\Win\System32\notepad.exe",
            // Browser profile data (NOT caches).
            @"C:\L\Google\Chrome\User Data\Default\Login Data",
            @"C:\L\Google\Chrome\User Data\Default\History",
            @"C:\L\Google\Chrome\User Data\Default\Bookmarks",
            @"C:\R\Mozilla\Firefox\Profiles\abc\places.sqlite",
            // Live databases and mailboxes.
            @"C:\U\Docs\mail.pst",
            @"C:\U\Docs\photos.db",
            @"C:\L\MailApp\store.ost",
            // User documents and media.
            @"C:\U\Docs\thesis.docx",
            @"C:\U\Pics\wedding.mp4",
            @"C:\U\Music\song.flac",
            @"C:\U\Desktop\notes.txt",
            @"C:\U\Videos\recording.mkv",
            @"C:\U\OneDrive\work.xlsx",
            // System files (recent dumps are NEVER via the age gate,
            // covered in AgeGates; a 400-day dump here is rightly SAFE).
            @"C:\hiberfil.sys",
            @"C:\pagefile.sys",
            // Protected kinds at huge size/age: kind beats size hunger.
            @"C:\U\Docs\big-project.zip",
            @"C:\PF\Game\big.dat",
            // Explicit Never-list entry.
            @"C:\Keep\anything.bin",
        ];

        var hits = new List<string>();
        foreach (string path in corpus)
        {
            var got = c.Classify(Fp(path, ageDays: 400, size: 500L * 1024 * 1024), Now);
            if (got.Tier != RiskTier.Never)
            {
                hits.Add($"{path} -> {got.Tier} ({string.Join(",", got.RuleIds)})");
            }
        }

        // Even huge, ancient corpus files must never be recommended:
        // tier is about KIND, not size hunger.
        Assert.True(hits.Count == 0, "Corpus hits (STOP):\n" + string.Join("\n", hits));
    }

    [Fact]
    public void NeverList_Wins_Over_SafeRules()
    {
        var c = TestClassifier([@"C:\Temp\keepme"]);
        var got = c.Classify(Fp(@"C:\Temp\keepme\a.tmp"), Now);
        Assert.Equal(RiskTier.Never, got.Tier);
        Assert.Contains("N-neverlist", got.RuleIds);
    }

    [Fact]
    public void BrowserCache_OutsideProfile_StaysNever()
    {
        // A06: the S-browsercache carveout is for BROWSER caches.
        // A "Cache" dir anywhere else is unknown content — N-unknown,
        // never a cleanup recommendation. (Profile caches stay SAFE:
        // pinned in SafeRules_Classify_KnownRegenerable.)
        var c = TestClassifier();
        var game = c.Classify(Fp(@"C:\Games\Foo\Cache\textures.dat"), Now);
        Assert.Equal(RiskTier.Never, game.Tier);
        Assert.Contains("N-unknown", game.RuleIds);
        var code = c.Classify(Fp(@"C:\Work\proj\Code Cache\blob.bin"), Now);
        Assert.Equal(RiskTier.Never, code.Tier);
        Assert.Contains("N-unknown", code.RuleIds);
        var shader = c.Classify(Fp(@"C:\Tools\ShaderCache\a.bin"), Now);
        Assert.Equal(RiskTier.Never, shader.Tier);
        Assert.Contains("N-unknown", shader.RuleIds);
    }

    [Fact]
    public void UnknownPaths_Default_Never_WithReasons()
    {
        var c = TestClassifier();
        var got = c.Classify(Fp(@"C:\Somewhere\weird.xyz"), Now);
        Assert.Equal(RiskTier.Never, got.Tier);
        Assert.Contains("N-unknown", got.RuleIds);
        Assert.NotEmpty(got.Reasons);
    }

    [Fact]
    public void Classifier_Survives_TempFixture_EndToEnd()
    {
        // Category (b): real files under %TEMP%, classified by the
        // production-constructed classifier (real machine roots).
        string root = Path.Combine(Path.GetTempPath(), "sentinel-r1-" + Guid.NewGuid().ToString("N"));
        string sub = Path.Combine(root, "Cache");
        Directory.CreateDirectory(sub);
        string a = Path.Combine(root, "a.tmp");
        string b = Path.Combine(sub, "data_1");
        File.WriteAllBytes(a, [1, 2, 3]);
        File.WriteAllBytes(b, [4, 5]);
        try
        {
            var prod = new RiskClassifier();
            var fa = new Fingerprint(a, 3, DateTime.UtcNow.Ticks, null, 1);
            var fb = new Fingerprint(b, 2, DateTime.UtcNow.Ticks, null, 1);
            Assert.Equal(RiskTier.Safe, prod.Classify(fa, DateTime.UtcNow).Tier);
            // Unknown subdir of temp is still under %TEMP% -> SAFE.
            Assert.Equal(RiskTier.Safe, prod.Classify(fb, DateTime.UtcNow).Tier);
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }

    [Fact]
    public void Orphan_InstalledApp_IsNeverALeftover()
    {
        var entries = new List<UninstallEntry>
        {
            new("OldApp 2.1", @"C:\PF\OldApp", null, null),
            new("ToolX", null, null, "\"C:\\Tools\\ToolX\\uninstall.exe\" /S"),
        };

        Assert.False(OrphanHunter.Evaluate(
            @"C:\PF\OldApp", Now.AddDays(-400), Now, entries).IsPossibleLeftover);
        Assert.False(OrphanHunter.Evaluate(
            @"C:\Tools\ToolX", Now.AddDays(-400), Now, entries).IsPossibleLeftover);
        // Name-only match (no recorded location) still protects.
        Assert.False(OrphanHunter.Evaluate(
            @"C:\PD\OldApp", Now.AddDays(-400), Now, entries).IsPossibleLeftover);
    }

    [Fact]
    public void Orphan_AbandonedDir_Surfaces_WithSignals()
    {
        var verdict = OrphanHunter.Evaluate(
            @"C:\PD\DeadApp", Now.AddDays(-400), Now, [],
            quietDays: 180);

        Assert.True(verdict.IsPossibleLeftover);
        Assert.Contains("NoUninstallEntry", verdict.Signals);
        Assert.Contains(verdict.Signals, s => s.StartsWith("Untouched"));
    }

    [Fact]
    public void Orphan_YoungDir_StaysProtected()
    {
        var verdict = OrphanHunter.Evaluate(
            @"C:\PD\NewPortable", Now.AddDays(-10), Now, [],
            quietDays: 180);

        Assert.False(verdict.IsPossibleLeftover);
        Assert.Contains("RecentlyActive", verdict.Signals);
    }

    [Fact]
    public void UninstallEntries_Read_WithWellformedRows()
    {
        var entries = OrphanHunter.ReadUninstallEntries();

        Assert.NotEmpty(entries);
        Assert.All(entries, e => Assert.False(string.IsNullOrWhiteSpace(e.DisplayName)));
    }

    [Fact]
    public void Duplicates_GroupByHash_PrimaryIsRealOne()
    {
        var files = new List<Fingerprint>
        {
            new(@"C:\U\Downloads\setup.exe", 10_000_000, Now.AddDays(-5).Ticks, "HASH1", 1),
            new(@"C:\PF\App\setup.exe", 10_000_000, Now.AddDays(-100).Ticks, "HASH1", 1),
            new(@"C:\U\Docs\setup.exe", 10_000_000, Now.AddDays(-50).Ticks, "HASH1", 1),
            new(@"C:\Temp\setup.exe", 10_000_000, Now.AddDays(-1).Ticks, "HASH1", 1),
            new(@"C:\U\Docs\unique.txt", 100, Now.Ticks, "HASH2", 1),
            new(@"C:\U\Docs\unhashed.bin", 10_000_000, Now.Ticks, null, 1),
            new(@"C:\A\tiny1.bin", 100, Now.Ticks, "HASH3", 1),
            new(@"C:\B\tiny2.bin", 100, Now.Ticks, "HASH3", 1),
        };
        var groups = DuplicateFinder.FindByHash(
            files, [@"C:\PF", @"C:\Win", @"C:\U\Docs", @"C:\U\Downloads", @"C:\Temp"]);

        var group = Assert.Single(groups);
        Assert.Equal("HASH1", group.Hash);
        Assert.Equal(4, group.CopyCount);
        // App-owned copy wins even though it is the oldest; user
        // files beat downloads; temp always loses.
        Assert.Equal(@"C:\PF\App\setup.exe", group.CopiesOrdered[0]);
        Assert.Equal(@"C:\U\Docs\setup.exe", group.CopiesOrdered[1]);
        Assert.Equal(@"C:\U\Downloads\setup.exe", group.CopiesOrdered[2]);
        Assert.Equal(@"C:\Temp\setup.exe", group.CopiesOrdered[3]);
    }

    [Fact]
    public void Classifier_OrphanCarveout_YieldsReviewNeverSafe()
    {
        var c = TestClassifier();
        bool Orphan(string p) => p.StartsWith(@"C:\PD\DEADAPP", StringComparison.Ordinal);

        var orphaned = c.Classify(Fp(@"C:\PD\DeadApp\data.bin", ageDays: 400), Now, Orphan);
        Assert.Equal(RiskTier.Review, orphaned.Tier);
        Assert.Contains("R-orphan", orphaned.RuleIds);

        var kept = c.Classify(Fp(@"C:\PD\DeadApp\data.bin", ageDays: 400), Now);
        Assert.Equal(RiskTier.Never, kept.Tier);

        // SAFE still beats the orphan verdict: temp is temp.
        var temp = c.Classify(Fp(@"C:\Temp\x.tmp", ageDays: 400), Now, _ => true);
        Assert.Equal(RiskTier.Safe, temp.Tier);
    }
}
