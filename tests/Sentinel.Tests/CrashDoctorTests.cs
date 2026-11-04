using Sentinel.Engine.CrashDoctor;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.Tests;

// Crash Doctor pack v1 tests: pack integrity, explainer grounding,
// and the 04 citation gate — every crash answer cites an event or
// a pack entry; uncited causal claims are flagged, never shipped.
public sealed class CrashDoctorTests
{
    private static readonly DateTime Now = new(2026, 10, 30, 12, 0, 0, DateTimeKind.Utc);

    private static TargetedEventRecord Ev(
        string provider, int id, long recordId, DateTime time,
        string message = "", params string[] properties) =>
        new("System", recordId, id, "Error", time, provider, message, properties);

    [Fact]
    public void Pack_HasVersion_And_WellformedEntries()
    {
        Assert.Matches(@"^\d+\.\d+\.\d+$", KnowledgePack.PackVersion);

        uint[] codes = [0x124, 0x133, 0xEF, 0x50, 0x7E, 0x3B, 0x1E, 0x139, 0x9F, 0xD1, 0xA, 0x24, 0x7A, 0x116];
        foreach (uint code in codes)
        {
            var entry = KnowledgePack.FindBugCheck(code);
            Assert.NotNull(entry);
            Assert.False(string.IsNullOrWhiteSpace(entry!.Title));
            Assert.NotEmpty(entry.Causes);
            Assert.NotEmpty(entry.Prevention);
            Assert.All(entry.Causes, c =>
            {
                Assert.False(string.IsNullOrWhiteSpace(c.Text));
                Assert.False(string.IsNullOrWhiteSpace(c.RaiseWhen));
            });
        }

        Assert.NotNull(KnowledgePack.FindEvent("Microsoft-Windows-Kernel-Power", 41));
        Assert.NotNull(KnowledgePack.FindEvent("EventLog", 6008));
        Assert.NotNull(KnowledgePack.FindEvent("Application Error", 1000));
        Assert.NotNull(KnowledgePack.FindEvent("NTFS", 55));
        Assert.NotNull(KnowledgePack.FindEvent("disk", 153));
    }

    [Fact]
    public void Pack_Misses_Honestly_NeverInvents()
    {
        Assert.Null(KnowledgePack.FindBugCheck(0xABC));
        Assert.Null(KnowledgePack.FindEvent("Nope-Provider", 9999));
        Assert.Null(KnowledgePack.FindVendor("mysterydrv.sys"));
        Assert.Equal("NVIDIA graphics driver", KnowledgePack.FindVendor("NVLDDMKM.SYS"));
    }

    [Fact]
    public void BugCheck1001_Links_Code_Module_And_Pack()
    {
        var anchor = Ev(
            "Microsoft-Windows-WER-SystemErrorReporting", 1001, 500, Now,
            "The computer has rebooted from a bugcheck.",
            "0x133", "0x1", "0x2", "0x3", "0x4");

        var card = CrashExplainer.Explain(anchor, [anchor]);

        Assert.Contains("0x133", card.WhatHappened);
        Assert.NotEmpty(card.Findings);
        Assert.All(card.Findings, f => Assert.Contains(f.Citations, c => c.Kind == "pack"));
        Assert.NotEmpty(card.Prevention);
        Assert.Empty(CitationValidator.FindUncited(card));
    }

    [Fact]
    public void BugCheck_WithNamedModule_RaisesConfidence_AndNamesVendor()
    {
        var anchor = Ev(
            "Microsoft-Windows-WER-SystemErrorReporting", 1001, 501, Now,
            "Bugcheck 0xD1 caused by nvlddmkm.sys",
            "209", "0x0", "0x2", "0x0", "0x0");

        var card = CrashExplainer.Explain(anchor, [anchor]);

        var finding = Assert.Single(card.Findings);
        Assert.Equal(KnowledgePack.Confidence.High, finding.Confidence);
        Assert.Contains("nvlddmkm.sys", finding.Cause);
        Assert.Contains("NVIDIA", finding.Cause);
    }

    [Fact]
    public void UnknownModule_And_UnknownCode_YieldHonestGaps()
    {
        var anchor = Ev(
            "Microsoft-Windows-WER-SystemErrorReporting", 1001, 502, Now,
            "Bugcheck 0xABC caused by mysterydrv.sys",
            "0xABC");

        var card = CrashExplainer.Explain(anchor, [anchor]);

        Assert.Empty(card.Findings); // No pack entry -> no invented cause.
        Assert.Contains(card.HonestGaps, g => g.Contains("0xABC"));
        Assert.Contains(card.HonestGaps, g => g.Contains("mysterydrv.sys"));
        Assert.Empty(CitationValidator.FindUncited(card));
    }

    [Fact]
    public void KernelPower41_Explains_WithPackEntry()
    {
        var anchor = Ev("Microsoft-Windows-Kernel-Power", 41, 600, Now, "The system rebooted without cleanly shutting down.");

        var card = CrashExplainer.Explain(anchor, [anchor]);

        Assert.NotEmpty(card.Findings);
        Assert.All(card.Findings, f => Assert.Contains(f.Citations, c => c.Reference == "EV:Kernel-Power#41"));
        Assert.Contains("First sighting", card.Trend, StringComparison.OrdinalIgnoreCase);
    }

    // P2-03 contract change (was Repeats_WorsenTrend_AndRaiseMediumCauses):
    // repetition feeds the trend line (frequency), never confidence.
    // A repeated symptom is not a confirmed cause.
    [Fact]
    public void Repeats_WorsenTrend_WithoutRaisingCauses()
    {
        var old1 = Ev("Microsoft-Windows-Kernel-Power", 41, 601, Now.AddDays(-6));
        var old2 = Ev("Microsoft-Windows-Kernel-Power", 41, 602, Now.AddDays(-2));
        var anchor = Ev("Microsoft-Windows-Kernel-Power", 41, 603, Now);

        var card = CrashExplainer.Explain(anchor, [old1, old2, anchor]);

        Assert.Contains("3 times", card.Trend);
        Assert.Equal(3, card.Findings.Count);
        Assert.DoesNotContain(card.Findings, f => f.Confidence == KnowledgePack.Confidence.High);
        Assert.Contains(card.Findings, f => f.Confidence == KnowledgePack.Confidence.Medium);
    }

    // P2-03: same-device recurrence ANCHORS (provider + device +
    // time all match). Only the disk cause rises — and the raise
    // cites the corroborating disk events, not just the pack.
    [Fact]
    public void Disk_SameDevice_Anchors_Raise_With_EventCitations()
    {
        var anchor = Ev(
            "Microsoft-Windows-WER-SystemErrorReporting", 1001, 700, Now,
            "The computer has rebooted from a bugcheck.", "0xEF");
        var disk1 = Ev(
            "disk", 153, 701, Now.AddHours(-3),
            "The IO operation at logical block address 0x1234 for Disk 2 was retried.");
        var disk2 = Ev(
            "disk", 153, 702, Now.AddHours(-1),
            "The IO operation at logical block address 0x5678 for Disk 2 was retried.");

        var card = CrashExplainer.Explain(anchor, [disk1, disk2, anchor]);

        Assert.Equal(3, card.Findings.Count);
        var disk = Assert.Single(
            card.Findings, f => f.Cause.Contains("failing disk corrupted data"));
        Assert.Equal(KnowledgePack.Confidence.High, disk.Confidence);
        Assert.Contains(disk.Citations, c => c.Kind == "pack");
        Assert.Equal(2, disk.Citations.Count(c => c.Kind == "event"));
        foreach (var other in card.Findings.Where(f => f != disk))
        {
            Assert.Equal(KnowledgePack.Confidence.Medium, other.Confidence);
            Assert.DoesNotContain(other.Citations, c => c.Kind == "event");
        }

        Assert.DoesNotContain(card.HonestGaps, g => g.Contains("not corroborating"));
    }

    // P2-03: a single disk hit anchors when the crash anchor names
    // the same device (anchor-side device match).
    [Fact]
    public void Disk_AnchorNamedDevice_Anchors_SingleHit()
    {
        var anchor = Ev(
            "Microsoft-Windows-WER-SystemErrorReporting", 1001, 710, Now,
            "Bugcheck 0xEF during paging on Disk 0.", "0xEF");
        var disk = Ev(
            "disk", 153, 711, Now.AddHours(-2),
            "The IO operation for Disk 0 was retried.");

        var card = CrashExplainer.Explain(anchor, [disk, anchor]);

        var raised = Assert.Single(
            card.Findings, f => f.Cause.Contains("failing disk corrupted data"));
        Assert.Equal(KnowledgePack.Confidence.High, raised.Confidence);
        Assert.Contains(raised.Citations, c => c.Kind == "event");
    }

    // P2-03 unrelated-device fixture: warnings on DIFFERENT devices
    // (Disk 1 vs volume D:) with the anchor naming neither. Nearby
    // in time only: observed + gapped, never a raise.
    [Fact]
    public void Disk_UnrelatedDevices_DoNotRaise_GapRecorded()
    {
        var anchor = Ev(
            "Microsoft-Windows-WER-SystemErrorReporting", 1001, 720, Now,
            "The computer has rebooted from a bugcheck.", "0xEF");
        var disk = Ev(
            "disk", 153, 721, Now.AddHours(-3),
            "The IO operation for Disk 1 was retried.");
        var ntfs = Ev(
            "NTFS", 55, 722, Now.AddHours(-1),
            "The file system structure on volume D: is corrupt.");

        var card = CrashExplainer.Explain(anchor, [disk, ntfs, anchor]);

        Assert.All(card.Findings, f =>
            Assert.Equal(KnowledgePack.Confidence.Medium, f.Confidence));
        Assert.Contains(card.HonestGaps, g => g.Contains("not corroborating"));
    }

    // P2-03 provider anchor: event IDs are provider-scoped. A 153
    // from a foreign provider is NOT a disk warning — ignored
    // entirely (no raise, no disk gap).
    [Fact]
    public void Disk_ForeignProvider_Is_Not_A_Disk_Warning()
    {
        var anchor = Ev(
            "Microsoft-Windows-WER-SystemErrorReporting", 1001, 730, Now,
            "The computer has rebooted from a bugcheck.", "0xEF");
        var fake = Ev("Contoso-Fake", 153, 731, Now.AddHours(-1), "Something 153-ish.");

        Assert.False(CrashExplainer.IsDiskWarning(fake));
        var card = CrashExplainer.Explain(anchor, [fake, anchor]);

        Assert.All(card.Findings, f =>
            Assert.Equal(KnowledgePack.Confidence.Medium, f.Confidence));
        Assert.DoesNotContain(card.HonestGaps, g => g.Contains("disk warning"));
    }

    // P2-03 competing-cause fixture: repeats + anchored disk
    // evidence together. Repetition promotes NOTHING; the anchored
    // disk cause rises alone while its competitors stay Medium.
    [Fact]
    public void BugCheck_Repeats_Promote_Nothing_AnchoredDisk_Rises_Alone()
    {
        var rep1 = Ev(
            "Microsoft-Windows-WER-SystemErrorReporting", 1001, 740, Now.AddDays(-5),
            "The computer has rebooted from a bugcheck.", "0xEF");
        var rep2 = Ev(
            "Microsoft-Windows-WER-SystemErrorReporting", 1001, 741, Now.AddDays(-2),
            "The computer has rebooted from a bugcheck.", "0xEF");
        var anchor = Ev(
            "Microsoft-Windows-WER-SystemErrorReporting", 1001, 742, Now,
            "The computer has rebooted from a bugcheck.", "0xEF");
        var disk1 = Ev(
            "disk", 153, 743, Now.AddHours(-4),
            "The IO operation for Disk 3 (PDO name: \\Device\\Harddisk3\\DR3) was retried.");
        var disk2 = Ev(
            "disk", 153, 744, Now.AddHours(-1),
            "The IO operation for Disk 3 (PDO name: \\Device\\Harddisk3\\DR3) was retried.");

        var card = CrashExplainer.Explain(anchor, [rep1, rep2, disk1, disk2, anchor]);

        Assert.Contains("3 sightings", card.Trend); // frequency still reported.
        var disk = Assert.Single(
            card.Findings, f => f.Confidence == KnowledgePack.Confidence.High);
        Assert.Contains("failing disk", disk.Cause);
        Assert.Equal(2, card.Findings.Count(f =>
            f.Confidence == KnowledgePack.Confidence.Medium));
    }

    // P2-03: device-token extraction is conservative — real naming
    // shapes tokenize, prose without devices yields nothing.
    [Fact]
    public void ParseDeviceTokens_Extracts_Conservative_Shapes()
    {
        var tokens = CrashExplainer.ParseDeviceTokens(
            "IO for Disk 2 (PDO name: \\Device\\Harddisk2\\DR2) was retried.");

        Assert.Contains("DISK 2", tokens);
        Assert.Contains("HARDDISK2", tokens);
        Assert.Contains("DR2", tokens);
        Assert.Contains("\\DEVICE\\HARDDISK2\\DR2", tokens);

        var vol = CrashExplainer.ParseDeviceTokens(
            "The file system structure on volume C: is corrupt.");
        Assert.Contains("VOLUME C:", vol);

        Assert.Empty(CrashExplainer.ParseDeviceTokens("The computer has rebooted from a bugcheck."));
    }

    [Fact]
    public void CitationValidator_Flags_UncitedDrafts()
    {
        var bad = new CrashCard(
            "t", "w",
            [new CrashFinding("mystery cause", KnowledgePack.Confidence.Low, [])],
            [], "trend", [], []);

        var flagged = CitationValidator.FindUncited(bad);

        Assert.Single(flagged);
    }

    [Fact]
    public void ParseBugCheckCode_Reads_Hex_And_Decimal()
    {
        Assert.Equal(0x133u, CrashExplainer.ParseBugCheckCode(Ev("p", 1001, 1, Now, "", "0x133")));
        Assert.Equal(209u, CrashExplainer.ParseBugCheckCode(Ev("p", 1001, 2, Now, "", "209")));
        Assert.Null(CrashExplainer.ParseBugCheckCode(Ev("p", 1001, 3, Now, "", "nope")));
    }

    [Fact]
    public void ParseImplicatedModule_Finds_DriverFile()
    {
        Assert.Equal(
            "nvlddmkm.sys",
            CrashExplainer.ParseImplicatedModule(Ev("p", 1001, 1, Now, "fault in nvlddmkm.sys while paging")));
        Assert.Null(CrashExplainer.ParseImplicatedModule(Ev("p", 1001, 2, Now, "no module here")));
    }
}
