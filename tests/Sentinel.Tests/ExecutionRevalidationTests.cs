using Sentinel.Engine.Actions;
using Sentinel.Engine.Policy;

namespace Sentinel.Tests;

// E31: execution-time revalidation. The approval is evidence for
// comparison, never a shortcut — fingerprint, generation, signer,
// locks, placeholders, scope, and tier are all re-checked against
// live state, and the first failure refuses with a reason.
public sealed class ExecutionRevalidationTests : IDisposable
{
    private readonly string _root;
    private bool _disposed;

    public ExecutionRevalidationTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "sentinel-e31-" + Guid.NewGuid().ToString("N"));
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
            // Best effort: temp cleanup never fails the test.
        }
    }

    private sealed class FixedSigner : ISignerReader
    {
        private readonly string? _subject;

        public FixedSigner(string? subject)
        {
            _subject = subject;
        }

        public string? ReadSubject(string path) => _subject;
    }

    private sealed class ThrowingSigner : ISignerReader
    {
        public string? ReadSubject(string path) => throw new IOException("no signer store");
    }

    private string WriteTemp(string name, string content = "junk-bytes")
    {
        string path = Path.Combine(_root, name);
        File.WriteAllText(path, content);
        return path;
    }

    private static (ActionTarget Target, ActionApproval Approval) ApprovedFor(
        string path, string? signer = null, RiskTier tier = RiskTier.Safe,
        long generation = 7, IReadOnlyList<string>? roots = null)
    {
        var info = new FileInfo(path);
        var target = new ActionTarget(
            "f:1", path, "file", tier,
            info.Length, info.LastWriteTimeUtc.Ticks, signer);
        var approval = new ActionApproval(
            "clean_items_to_vault", [target],
            roots ?? [Path.GetDirectoryName(path)!], [],
            generation, DateTimeOffset.UtcNow,
            ActionActors.User, Guid.NewGuid().ToString("N"));
        return (target, approval);
    }

    private static ActionTemplate CleanTemplate() =>
        ActionRegistry.Find("clean_items_to_vault")!;

    [Fact]
    public void PassPath_UnchangedTempFile_MayProceed()
    {
        string path = WriteTemp("junk.tmp");
        var (target, approval) = ApprovedFor(path);

        var result = ExecutionRevalidator.RevalidateForExecution(
            path, target, approval, CleanTemplate(), new RiskClassifier(),
            DateTime.UtcNow, new FixedSigner(null), currentGeneration: 7);

        Assert.True(result.MayProceed);
        Assert.Equal(ActionRevalidationVerdict.Ok, result.Verdict);
        Assert.Equal(ExecutionExtendedCode.None, result.Extended);
        Assert.Equal(RiskTier.Safe, result.Current.Tier);
    }

    [Fact]
    public void FingerprintChanged_SizeDiffers_Refused()
    {
        string path = WriteTemp("grows.tmp");
        var (target, approval) = ApprovedFor(path);
        File.AppendAllText(path, "more-bytes");

        var result = ExecutionRevalidator.RevalidateForExecution(
            path, target, approval, CleanTemplate(), new RiskClassifier(),
            DateTime.UtcNow, new FixedSigner(null));

        Assert.False(result.MayProceed);
        Assert.Equal(ExecutionExtendedCode.FingerprintChanged, result.Extended);
        Assert.Contains("changed since you confirmed", result.Detail);
    }

    [Fact]
    public void FingerprintChanged_MtimeDiffers_Refused()
    {
        string path = WriteTemp("touched.tmp");
        var (target, approval) = ApprovedFor(path);
        File.SetLastWriteTimeUtc(path, DateTime.UtcNow - TimeSpan.FromDays(2));

        var result = ExecutionRevalidator.RevalidateForExecution(
            path, target, approval, CleanTemplate(), new RiskClassifier(),
            DateTime.UtcNow, new FixedSigner(null));

        Assert.False(result.MayProceed);
        Assert.Equal(ExecutionExtendedCode.FingerprintChanged, result.Extended);
    }

    [Fact]
    public void GenerationChanged_NewerScan_Refused()
    {
        string path = WriteTemp("stale.tmp");
        var (target, approval) = ApprovedFor(path, generation: 7);

        var result = ExecutionRevalidator.RevalidateForExecution(
            path, target, approval, CleanTemplate(), new RiskClassifier(),
            DateTime.UtcNow, new FixedSigner(null), currentGeneration: 8);

        Assert.False(result.MayProceed);
        Assert.Equal(ExecutionExtendedCode.GenerationChanged, result.Extended);
        Assert.Contains("newer scan", result.Detail);
    }

    [Fact]
    public void GenerationUnknown_SkipsCheck_Proceeds()
    {
        string path = WriteTemp("nogen.tmp");
        var (target, approval) = ApprovedFor(path, generation: 7);

        var result = ExecutionRevalidator.RevalidateForExecution(
            path, target, approval, CleanTemplate(), new RiskClassifier(),
            DateTime.UtcNow, new FixedSigner(null), currentGeneration: null);

        Assert.True(result.MayProceed);
    }

    [Fact]
    public void SignerChanged_Refused()
    {
        string path = WriteTemp("resigned.tmp");
        var (target, approval) = ApprovedFor(path, signer: "CN=Original Signer");

        var result = ExecutionRevalidator.RevalidateForExecution(
            path, target, approval, CleanTemplate(), new RiskClassifier(),
            DateTime.UtcNow, new FixedSigner("CN=Somebody Else"));

        Assert.False(result.MayProceed);
        Assert.Equal(ExecutionExtendedCode.SignerChanged, result.Extended);
        Assert.Contains("signature changed", result.Detail);
    }

    [Fact]
    public void SignerMatch_Proceeds()
    {
        string path = WriteTemp("signed.tmp");
        var (target, approval) = ApprovedFor(path, signer: "CN=Same Signer");

        var result = ExecutionRevalidator.RevalidateForExecution(
            path, target, approval, CleanTemplate(), new RiskClassifier(),
            DateTime.UtcNow, new FixedSigner("CN=Same Signer"));

        Assert.True(result.MayProceed);
    }

    [Fact]
    public void SignerExpectedNull_SkipsCheck_ReaderNeverCalled()
    {
        string path = WriteTemp("unsigned.tmp");
        var (target, approval) = ApprovedFor(path, signer: null);

        var result = ExecutionRevalidator.RevalidateForExecution(
            path, target, approval, CleanTemplate(), new RiskClassifier(),
            DateTime.UtcNow, new ThrowingSigner());

        Assert.True(result.MayProceed);
    }

    [Fact]
    public void SignerReadThrows_TreatedAsChanged_Refused()
    {
        string path = WriteTemp("unreadable-sig.tmp");
        var (target, approval) = ApprovedFor(path, signer: "CN=Original Signer");

        var result = ExecutionRevalidator.RevalidateForExecution(
            path, target, approval, CleanTemplate(), new RiskClassifier(),
            DateTime.UtcNow, new ThrowingSigner());

        Assert.False(result.MayProceed);
        Assert.Equal(ExecutionExtendedCode.SignerChanged, result.Extended);
    }

    [Fact]
    public void LockedFile_OpenElsewhere_Refused()
    {
        string path = WriteTemp("locked.tmp");
        var (target, approval) = ApprovedFor(path);

        using var hold = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var result = ExecutionRevalidator.RevalidateForExecution(
            path, target, approval, CleanTemplate(), new RiskClassifier(),
            DateTime.UtcNow, new FixedSigner(null));

        Assert.False(result.MayProceed);
        Assert.Equal(ExecutionExtendedCode.Locked, result.Extended);
        Assert.Contains("open in another program", result.Detail);
    }

    [Fact]
    public void DeletedFile_RefusedUnreadable()
    {
        string path = WriteTemp("gone.tmp");
        var (target, approval) = ApprovedFor(path);
        File.Delete(path);

        var result = ExecutionRevalidator.RevalidateForExecution(
            path, target, approval, CleanTemplate(), new RiskClassifier(),
            DateTime.UtcNow, new FixedSigner(null));

        Assert.False(result.MayProceed);
        Assert.Equal(ActionRevalidationVerdict.Unreadable, result.Verdict);
    }

    [Fact]
    public void OfflineFile_RefusedAsPlaceholder()
    {
        string path = WriteTemp("offline.tmp");
        var (target, approval) = ApprovedFor(path);
        File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.Offline);
        try
        {
            // If the filesystem ignored the bit, the test proves
            // nothing — fail loudly instead of passing vacuously.
            Assert.True(FileFlags.IsOffline(File.GetAttributes(path)),
                "The filesystem refused the Offline bit; placeholder branch untested.");

            var result = ExecutionRevalidator.RevalidateForExecution(
                path, target, approval, CleanTemplate(), new RiskClassifier(),
                DateTime.UtcNow, new FixedSigner(null));

            Assert.False(result.MayProceed);
            Assert.Equal(ExecutionExtendedCode.Placeholder, result.Extended);
        }
        finally
        {
            File.SetAttributes(path, File.GetAttributes(path) & ~FileAttributes.Offline);
        }
    }

    [Fact]
    public void SeamPassthrough_OutOfScope_Propagates()
    {
        string path = WriteTemp("scoped.tmp");
        string other = Path.Combine(Path.GetTempPath(), "sentinel-e31-other-" + Guid.NewGuid().ToString("N"));
        var (target, approval) = ApprovedFor(path, roots: [other]);

        var result = ExecutionRevalidator.RevalidateForExecution(
            path, target, approval, CleanTemplate(), new RiskClassifier(),
            DateTime.UtcNow, new FixedSigner(null));

        Assert.False(result.MayProceed);
        Assert.Equal(ActionRevalidationVerdict.OutOfScope, result.Verdict);
        Assert.Equal(ExecutionExtendedCode.None, result.Extended);
    }

    [Fact]
    public void SeamPassthrough_TierDrift_Propagates()
    {
        string path = WriteTemp("drift.tmp");
        var (target, approval) = ApprovedFor(path, tier: RiskTier.Review);

        var result = ExecutionRevalidator.RevalidateForExecution(
            path, target, approval, CleanTemplate(), new RiskClassifier(),
            DateTime.UtcNow, new FixedSigner(null));

        Assert.False(result.MayProceed);
        Assert.Equal(ActionRevalidationVerdict.TierChanged, result.Verdict);
        Assert.Equal(ExecutionExtendedCode.None, result.Extended);
    }

    [Fact]
    public void SeamPassthrough_NeverTouchDrift_Protected()
    {
        string path = WriteTemp("never.tmp");
        var (target, approval) = ApprovedFor(path);
        var classifier = new RiskClassifier(neverList: [_root]);

        var result = ExecutionRevalidator.RevalidateForExecution(
            path, target, approval, CleanTemplate(), classifier,
            DateTime.UtcNow, new FixedSigner(null));

        Assert.False(result.MayProceed);
        Assert.Equal(ActionRevalidationVerdict.Protected, result.Verdict);
    }

    [Fact]
    public void ElevationPolicy_CleanTemplate_MayRun()
    {
        Assert.True(ElevationPolicy.TemplateMayRun(CleanTemplate(), isElevated: false, out string reason));
        Assert.Empty(reason);
    }

    [Fact]
    public void ElevationPolicy_ElevationTemplate_RefusedWithReason()
    {
        var driver = ActionRegistry.Find("driver_rollback")!;
        Assert.False(ElevationPolicy.TemplateMayRun(driver, isElevated: false, out string reason));
        Assert.Contains("administrator", reason);

        // Elevation is checked before anything touches the disk, so
        // the target below is never even statted — only the refusal.
        string path = WriteTemp("driver.tmp");
        var (target, approval) = ApprovedFor(path);
        var result = ExecutionRevalidator.RevalidateForExecution(
            path, target, approval,
            driver, new RiskClassifier(), DateTime.UtcNow, new FixedSigner(null),
            elevationProbe: () => false);

        Assert.False(result.MayProceed);
        Assert.Equal(ExecutionExtendedCode.ElevationRequired, result.Extended);
    }

    [Theory]
    [InlineData(typeof(UnauthorizedAccessException), true)]
    [InlineData(typeof(IOException), false)]
    [InlineData(typeof(InvalidOperationException), false)]
    public void ElevationPolicy_DenialMapping(Type type, bool expected)
    {
        var ex = (Exception)Activator.CreateInstance(type, "x")!;
        Assert.Equal(expected, ElevationPolicy.IsElevationDenial(ex));
    }

    [Fact]
    public void FileFlags_PinnedBits()
    {
        Assert.Equal((FileAttributes)0x400000, FileFlags.RecallOnDataAccess);
        Assert.True(FileFlags.IsCloudPlaceholder(FileAttributes.Normal | FileFlags.RecallOnDataAccess));
        Assert.False(FileFlags.IsCloudPlaceholder(FileAttributes.Normal | FileAttributes.Offline));
        Assert.True(FileFlags.IsRecallable(FileAttributes.Offline));
        Assert.True(FileFlags.IsRecallable(FileAttributes.Normal | FileFlags.RecallOnDataAccess));
        Assert.False(FileFlags.IsRecallable(FileAttributes.Normal));
        Assert.False(FileFlags.IsRecallable(FileAttributes.ReadOnly | FileAttributes.Archive));
    }

    [Fact]
    public void ProductionSignerReader_UnsignedTempFile_ReturnsNull()
    {
        string path = WriteTemp("plain.tmp");
        var reader = new StaticEvidenceSignerReader();
        Assert.Null(reader.ReadSubject(path));
    }

    [Fact]
    public void DeadShortcut_WithScanFlags_ApprovedReview_Proceeds()
    {
        // The seam honors scan-computed flags: a dead link the table
        // shows as REVIEW re-checks as REVIEW at execution.
        string path = WriteTemp("dead.lnk");
        var (target, approval) = ApprovedFor(path, tier: RiskTier.Review);

        var result = ExecutionRevalidator.RevalidateForExecution(
            path, target, approval, CleanTemplate(), new RiskClassifier(),
            DateTime.UtcNow, new FixedSigner(null),
            attrFlagsLookup: _ => Sentinel.Store.FingerprintAttrs.DeadShortcut);

        Assert.True(result.MayProceed);
        Assert.Equal(RiskTier.Review, result.Current.Tier);
    }

    [Fact]
    public void DeadShortcut_WithoutScanFlags_ApprovedReview_TierChanged()
    {
        // ...and without the flags the same file reads SAFE (live
        // stat cannot recompute scan evidence), so a Review approval
        // refuses as TierChanged instead of executing blind. This is
        // why preview and execution always pass the DB lookup.
        string path = WriteTemp("dead2.lnk");
        var (target, approval) = ApprovedFor(path, tier: RiskTier.Review);

        var result = ExecutionRevalidator.RevalidateForExecution(
            path, target, approval, CleanTemplate(), new RiskClassifier(),
            DateTime.UtcNow, new FixedSigner(null));

        Assert.False(result.MayProceed);
        Assert.Equal(ActionRevalidationVerdict.TierChanged, result.Verdict);
    }
}
