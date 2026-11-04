using Sentinel.Store;

namespace Sentinel.Tests;

public sealed class StoreTests : IDisposable
{
    private readonly string _dbPath;
    private bool _disposed;

    public StoreTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), "sentinel-storetest-" + Guid.NewGuid().ToString("N") + ".db");
    }

    [Fact]
    public void Fingerprint_RoundTrip()
    {
        using var db = new SentinelDb(_dbPath);

        Assert.Null(db.GetFingerprint("C:\\x\\a.txt"));
        db.UpsertFingerprint("C:\\x\\a.txt", 10, 12345L, "ABC", generation: 1);

        var fp = db.GetFingerprint("C:\\x\\a.txt");
        Assert.NotNull(fp);
        Assert.Equal(10, fp.Size);
        Assert.Equal(12345L, fp.MTimeUtcTicks);
        Assert.Equal("ABC", fp.Hash);
        Assert.Equal(1, fp.LastSeenGeneration);

        db.UpsertFingerprint("C:\\x\\a.txt", 20, 999L, null, generation: 2);
        var updated = db.GetFingerprint("C:\\x\\a.txt")!;
        Assert.Equal(20, updated.Size);
        Assert.Null(updated.Hash);
        Assert.Equal(2, updated.LastSeenGeneration);
    }

    [Fact]
    public void ScanRun_BeginEnd()
    {
        using var db = new SentinelDb(_dbPath);

        var id = db.BeginRun("C:\\", generation: 7, mode: "Balanced");
        Assert.True(id > 0);
        db.EndRun(id, filesSeen: 3, bytesSeen: 100L, filesHashed: 1, durationMs: 50);
    }

    [Fact]
    public void ScanRun_Mode_RoundTrips()
    {
        using var db = new SentinelDb(_dbPath);

        var id = db.BeginRun("C:\\", generation: 1, mode: "Turbo");
        db.EndRun(id, filesSeen: 1, bytesSeen: 10L, filesHashed: 0, durationMs: 5);
        var run = db.GetRun(id)!;
        Assert.Equal("Turbo", run.Mode);
        Assert.Single(db.ListRuns(5), r => r.Mode == "Turbo");
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        try { File.Delete(_dbPath); } catch { /* best effort */ }
    }
}
