using Sentinel.App.ViewModels;
using Sentinel.Engine.SystemInventory;
using Sentinel.Engine.ThreatIntel;

namespace Sentinel.Tests;

// T53: selected-file local evidence → grounded explanation, plus
// the hash-reputation adapter contract with no wired egress
// (DEC-ANALYZER stays proposed_not_approved).
public sealed class FileInvestigationTests
{
    private static StaticFileEvidenceRecord SignedRecord() =>
        new(@"C:\a.exe", true, 1024, "ABCDEF", true, "Publisher Inc", "CA", null);

    private static StaticFileEvidenceRecord UnsignedRecord() =>
        new(@"C:\b.exe", true, 512, "123456", false, null, null, null);

    [Fact]
    public void Explain_Signed_Names_Origin_Not_Intent()
    {
        string text = ThreatsViewModel.ExplainFileEvidence(SignedRecord());

        Assert.Contains("Publisher Inc", text);
        Assert.Contains("origin, not intent", text);
        Assert.Contains("sent nowhere", text);
    }

    [Fact]
    public void Explain_Unsigned_Treats_With_Care()
    {
        string text = ThreatsViewModel.ExplainFileEvidence(UnsignedRecord());

        Assert.Contains("treat with care", text);
        Assert.Contains("freshly built", text);
        Assert.Contains("sent nowhere", text);
    }

    [Fact]
    public void Explain_Missing_Says_So()
    {
        var record = new StaticFileEvidenceRecord(
            @"C:\gone.exe", false, null, null, false, null, null, null);

        Assert.Contains("not present", ThreatsViewModel.ExplainFileEvidence(record));
    }

    [Fact]
    public void Explain_Hashless_Says_So()
    {
        var record = new StaticFileEvidenceRecord(
            @"C:\c.exe", true, 10, null, false, null, null, null);

        Assert.Contains("could not be computed", ThreatsViewModel.ExplainFileEvidence(record));
    }

    [Fact]
    public void Explain_Never_Calls_Unsigned_Safe_Or_Signed_Harmless()
    {
        string[] texts =
        [
            ThreatsViewModel.ExplainFileEvidence(SignedRecord()),
            ThreatsViewModel.ExplainFileEvidence(UnsignedRecord()),
            ThreatsViewModel.ExplainFileEvidence(new StaticFileEvidenceRecord(
                @"C:\g.exe", false, null, null, false, null, null, null)),
        ];

        foreach (string text in texts)
        {
            Assert.DoesNotContain("safe", text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("clean", text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("harmless", text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("malware", text, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void SetFileCheck_Fills_Explanation_And_Boundary()
    {
        var vm = new ThreatsViewModel();
        vm.SetFileCheck(vm.BeginFileCheck(), SignedRecord(), @"C:\a.exe", null);

        Assert.NotNull(vm.FileCheck);
        Assert.Contains("Publisher Inc", vm.FileCheck.Explanation);
        Assert.Contains("DEC-ANALYZER", vm.FileCheck.SecondOpinion);
    }

    [Fact]
    public void SetFileCheck_NullRecord_Explains_Failure()
    {
        var vm = new ThreatsViewModel();
        vm.SetFileCheck(vm.BeginFileCheck(), null, @"C:\a.exe", "locked");

        Assert.NotNull(vm.FileCheck);
        Assert.Contains("locked", vm.FileCheck.Explanation);
        Assert.Contains("sent nowhere", vm.FileCheck.SecondOpinion);
    }

    [Fact]
    public void ReputationRequest_Is_Hash_Only()
    {
        // The contract carries a fingerprint, never the file: no
        // path, name, content, or sample field may exist here.
        var names = typeof(FileReputationRequest).GetProperties()
            .Select(p => p.Name).OrderBy(n => n).ToList();

        Assert.Equal(["Sha256", "SizeBytes"], names);
    }

    [Fact]
    public async Task UnavailableAdapter_Always_Unknown_With_Reason()
    {
        IFileReputationAdapter adapter = new UnavailableReputationAdapter();

        var result = await adapter.LookupAsync(
            new FileReputationRequest("ABC", 10), CancellationToken.None);

        Assert.Equal(FileReputation.Unknown, result.Verdict);
        Assert.Contains("DEC-ANALYZER", result.Detail);
        Assert.Contains("sent nowhere", result.Detail);
        Assert.Contains("no approved destination", result.Source);
    }

    private sealed class FakeAdapter : IFileReputationAdapter
    {
        public ReputationDestination Destination { get; } =
            new("test-destination", "test policy");

        public Task<FileReputationResult> LookupAsync(
            FileReputationRequest request, CancellationToken ct) =>
            Task.FromResult(new FileReputationResult(
                FileReputation.KnownBad, Destination.Name,
                $"test service flags {request.Sha256}"));
    }

    [Fact]
    public async Task AdapterContract_Carries_Request_To_Result()
    {
        // The contract is usable: a future approved destination
        // plugs in here without changing callers.
        IFileReputationAdapter adapter = new FakeAdapter();

        var result = await adapter.LookupAsync(
            new FileReputationRequest("ABC", null), CancellationToken.None);

        Assert.Equal(FileReputation.KnownBad, result.Verdict);
        Assert.Contains("ABC", result.Detail);
    }
}
