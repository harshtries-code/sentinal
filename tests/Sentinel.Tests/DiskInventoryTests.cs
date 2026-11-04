using Sentinel.Engine.Inventory;
using Sentinel.Store;

namespace Sentinel.Tests;

// Fixture-tree tests for the read-only disk inventory (04 Phase 1).
// Fixtures live in %TEMP% and are removed in teardown; the product
// itself never writes to scanned paths.
public sealed class DiskInventoryTests : IDisposable
{
    private readonly string _root;
    private readonly string _dbPath;
    private bool _disposed;

    public DiskInventoryTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "sentinel-fixture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(_root, "sub", "deep"));
        File.WriteAllText(Path.Combine(_root, "a.txt"), "hello");
        File.WriteAllBytes(Path.Combine(_root, "sub", "b.bin"), new byte[256]);
        File.WriteAllText(Path.Combine(_root, "sub", "deep", "c.txt"), "world");
        _dbPath = Path.Combine(Path.GetTempPath(), "sentinel-test-" + Guid.NewGuid().ToString("N") + ".db");
    }

    [Fact]
    public async Task FindsAllFiles_WithCorrectSizes()
    {
        using var db = new SentinelDb(_dbPath);
        var scanner = new DiskInventoryScanner(db);

        var result = await scanner.ScanAsync(_root, generation: 1);

        Assert.Equal(3, result.FilesSeen);
        Assert.Equal(5 + 256 + 5, result.BytesSeen);
        Assert.Equal(3, result.FilesHashed);
        Assert.Empty(result.Gaps);
        var fp = db.GetFingerprint(Path.Combine(_root, "a.txt"));
        Assert.NotNull(fp);
        Assert.Equal(5, fp.Size);
        Assert.NotNull(fp.Hash);
        Assert.Equal(64, fp.Hash!.Length); // SHA256 hex
    }

    [Fact]
    public async Task SecondScan_HashesNothing()
    {
        using var db = new SentinelDb(_dbPath);
        var scanner = new DiskInventoryScanner(db);

        var first = await scanner.ScanAsync(_root, generation: 1);
        var second = await scanner.ScanAsync(_root, generation: 2);

        Assert.Equal(3, first.FilesHashed);
        Assert.Equal(0, second.FilesHashed);
        Assert.Equal(3, second.FilesSeen);
        Assert.Empty(second.Gaps);
    }

    [Fact]
    public async Task ModifiedFile_RehashedOnlyIt()
    {
        using var db = new SentinelDb(_dbPath);
        var scanner = new DiskInventoryScanner(db);

        await scanner.ScanAsync(_root, generation: 1);
        var before = db.GetFingerprint(Path.Combine(_root, "sub", "b.bin"))!;
        File.WriteAllBytes(Path.Combine(_root, "sub", "b.bin"), new byte[512]);

        var result = await scanner.ScanAsync(_root, generation: 2);

        Assert.Equal(1, result.FilesHashed);
        var after = db.GetFingerprint(Path.Combine(_root, "sub", "b.bin"))!;
        Assert.NotEqual(before.Hash, after.Hash);
        Assert.Equal(512, after.Size);
    }

    [SkippableFact]
    public async Task Junction_IsRecordedAsGap_NeverFollowed()
    {
        var target = Path.Combine(_root, "sub");
        var link = Path.Combine(_root, "linkdir");
        bool created;
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
            };
            using var proc = System.Diagnostics.Process.Start(psi)!;
            proc.WaitForExit(15000);
            created = proc.ExitCode == 0 && Directory.Exists(link);
        }
        catch
        {
            created = false;
        }

        Skip.IfNot(created, "mklink /J unavailable in this environment.");

        using var db = new SentinelDb(_dbPath);
        var scanner = new DiskInventoryScanner(db);

        var result = await scanner.ScanAsync(_root, generation: 1);

        Assert.Equal(3, result.FilesSeen); // Nothing under the link counted twice.
        Assert.Contains(result.Gaps, g => g.Path == link && g.Reason == "ReparsePointSkipped");
    }

    [SkippableFact]
    public async Task InaccessibleDirectory_IsGap_NotCrash()
    {
        var denied = Path.Combine(_root, "denied");
        Directory.CreateDirectory(denied);
        File.WriteAllText(Path.Combine(denied, "x.txt"), "nope");
        Skip.IfNot(RunCmd($"icacls \"{denied}\" /deny \"{Environment.UserName}:(R)\""),
            "icacls deny unavailable in this environment.");

        try
        {
            using var db = new SentinelDb(_dbPath);
            var scanner = new DiskInventoryScanner(db);

            var result = await scanner.ScanAsync(_root, generation: 1);

            Assert.Equal(3, result.FilesSeen);
            Assert.Contains(result.Gaps, g => g.Path == denied);
        }
        finally
        {
            RunCmd($"icacls \"{denied}\" /remove:d \"{Environment.UserName}\"");
        }
    }

    [SkippableFact]
    public async Task FileSymlink_IsGap_NeverHashed()
    {
        var target = Path.Combine(_root, "a.txt");
        var link = Path.Combine(_root, "link.txt");
        bool created;
        try
        {
            created = RunCmd($"mklink \"{link}\" \"{target}\"") && File.Exists(link);
        }
        catch
        {
            created = false;
        }

        Skip.IfNot(created, "File symlinks require privilege unavailable here.");

        using var db = new SentinelDb(_dbPath);
        var scanner = new DiskInventoryScanner(db);

        var result = await scanner.ScanAsync(_root, generation: 1);

        Assert.Equal(3, result.FilesSeen); // The link itself is not inventoried.
        Assert.Contains(result.Gaps, g => g.Path == link && g.Reason == "FileLinkSkipped");
        Assert.Null(db.GetFingerprint(link));
    }

    [SkippableFact]
    public async Task LinkedRoot_YieldsNothing_WithGap()
    {
        var link = Path.Combine(Path.GetTempPath(), "sentinel-linkroot-" + Guid.NewGuid().ToString("N"));
        bool created;
        try
        {
            created = RunCmd($"mklink /J \"{link}\" \"{_root}\"") && Directory.Exists(link);
        }
        catch
        {
            created = false;
        }

        Skip.IfNot(created, "mklink /J unavailable in this environment.");
        try
        {
            using var db = new SentinelDb(_dbPath);
            var scanner = new DiskInventoryScanner(db);

            var result = await scanner.ScanAsync(link, generation: 1);

            Assert.Equal(0, result.FilesSeen);
            Assert.Contains(result.Gaps, g => g.Reason == "LinkedRootSkipped");
        }
        finally
        {
            try { Directory.Delete(link); } catch { /* link only, never target */ }
        }
    }

    // Metadata and hashing are separate facts (10 §4): a failed
    // deep read keeps + counts the known stat with a MISSING hash,
    // and the next scan retries the hash instead of trusting null.
    [Fact]
    public async Task LockedFile_CountsMetadata_WithHashGap_ThenRehashes()
    {
        var locked = Path.Combine(_root, "locked.bin");
        File.WriteAllBytes(locked, new byte[1024]);
        using var db = new SentinelDb(_dbPath);
        var scanner = new DiskInventoryScanner(db);

        using (var hold = new FileStream(
            locked, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var result = await scanner.ScanAsync(_root, generation: 1);

            Assert.Equal(4, result.FilesSeen);
            Assert.Equal(5 + 256 + 5 + 1024, result.BytesSeen);
            Assert.Equal(3, result.FilesHashed);
            Assert.Contains(result.Gaps, g => g.Path == locked && g.Reason.StartsWith("HashFailed"));
            var fp = db.GetFingerprint(locked);
            Assert.NotNull(fp);
            Assert.Equal(1024, fp.Size);
            Assert.Null(fp.Hash); // Missing, never trusted.
        }

        var second = await scanner.ScanAsync(_root, generation: 2);

        Assert.Equal(1, second.FilesHashed); // Only the missing hash retried.
        Assert.Empty(second.Gaps);
        Assert.NotNull(db.GetFingerprint(locked)!.Hash);
    }

    [Fact]
    public void StableCheck_Requires_Pre_And_Post_Match()
    {
        Assert.True(DiskInventoryScanner.IsStable(100, 1000, 100, 1000));
        Assert.False(DiskInventoryScanner.IsStable(100, 1000, 200, 1000));
        Assert.False(DiskInventoryScanner.IsStable(100, 1000, 100, 2000));
    }

    private static bool RunCmd(string command)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c " + command)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
            };
            using var proc = System.Diagnostics.Process.Start(psi)!;
            proc.WaitForExit(15000);
            return proc.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        try { Directory.Delete(_root, recursive: true); } catch { /* best effort */ }
        try { File.Delete(_dbPath); } catch { /* best effort */ }
    }
}
