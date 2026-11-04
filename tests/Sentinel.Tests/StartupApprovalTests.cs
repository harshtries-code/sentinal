using Microsoft.Win32;
using Sentinel.App.ViewModels;
using Sentinel.Engine.Actions;
using Sentinel.Engine.SystemInventory;

namespace Sentinel.Tests;

// D45: honest read-only startup. Enable/disable state is OBSERVED
// (Task Manager's StartupApproved values), never inferred; boot
// context is measured from the tick counter; enable/disable
// templates stay Suspended with no UI workaround. Live-registry
// tests are read-only and assert the MAPPING (injected bytes →
// Enabled), never machine content.
public sealed class StartupApprovalTests
{
    [Theory]
    [InlineData(new byte[] { 0x02, 0x00, 0x00, 0x00 }, true)]
    [InlineData(new byte[] { 0x03, 0x00, 0x00, 0x00 }, false)]
    [InlineData(new byte[] { 0x06, 0x00, 0x00, 0x00 }, false)]
    [InlineData(new byte[] { 0x00 }, false)]
    public void ParseState_ByteRule(byte[] raw, bool expected)
    {
        Assert.Equal(expected, StartupApproval.ParseState(raw));
    }

    [Fact]
    public void ParseState_MissingOrEmpty_Unknown()
    {
        Assert.Null(StartupApproval.ParseState(null));
        Assert.Null(StartupApproval.ParseState([]));
    }

    [Theory]
    [InlineData("HKCU Run", RegistryHive.CurrentUser, "Run")]
    [InlineData("HKCU RunOnce", RegistryHive.CurrentUser, "Run")]
    [InlineData("HKLM Run", RegistryHive.LocalMachine, "Run")]
    [InlineData("HKLM RunOnce", RegistryHive.LocalMachine, "Run")]
    [InlineData("HKLM Run (32-bit)", RegistryHive.LocalMachine, "Run32")]
    [InlineData("Startup folder (user)", RegistryHive.CurrentUser, "StartupFolder")]
    [InlineData("Startup folder (all users)", RegistryHive.LocalMachine, "StartupFolder")]
    public void ShelfFor_MapsLocations(string location, RegistryHive hive, string subKey)
    {
        var shelf = StartupApproval.ShelfFor(location);
        Assert.NotNull(shelf);
        Assert.Equal(hive, shelf.Value.Hive);
        Assert.Equal(subKey, shelf.Value.SubKey);
    }

    [Fact]
    public void ShelfFor_UnknownLocation_Null()
    {
        Assert.Null(StartupApproval.ShelfFor("Scheduled tasks"));
    }

    // Deterministic script: name hash decides the injected bytes.
    private static byte[]? ScriptedBytes(string name)
    {
        int bucket = Math.Abs(name.GetHashCode(StringComparison.Ordinal)) % 3;
        return bucket switch
        {
            0 => [0x02, 0x00, 0x00, 0x00],
            1 => [0x03, 0x00, 0x00, 0x00],
            _ => null,
        };
    }

    [Fact]
    public void CollectRunKeys_InjectedApprovals_MapToEnabled()
    {
        var seen = new List<(RegistryHive Hive, string SubKey, string Name)>();
        var result = StartupCollector.CollectRunKeys((hive, subKey, name) =>
        {
            seen.Add((hive, subKey, name));
            return ScriptedBytes(name);
        });

        // Whatever this machine holds, every record's Enabled equals
        // the parse of its injected bytes — mapping, not content.
        foreach (var record in result.Records)
        {
            Assert.Equal(StartupApproval.ParseState(ScriptedBytes(record.Name)), record.Enabled);
        }

        Assert.DoesNotContain(result.Gaps, g => g.Reason == "ApprovalUnreadable");
    }

    [Fact]
    public void CollectRunKeys_ApprovalThrows_RecordsKeptOneGapPerLocation()
    {
        var result = StartupCollector.CollectRunKeys(
            (_, _, _) => throw new UnauthorizedAccessException("locked shelf"));

        // Entries are still listed; state reads unknown.
        Assert.All(result.Records, r => Assert.Null(r.Enabled));
        var approvalGaps = result.Gaps.Where(g => g.Reason == "ApprovalUnreadable").ToList();
        Assert.True(approvalGaps.Count <= 5);
        Assert.Equal(
            approvalGaps.Select(g => g.Source).Distinct().Count(),
            approvalGaps.Count);
    }

    [Fact]
    public void CollectStartupFolders_InjectedApprovals_MapToEnabled()
    {
        var result = StartupCollector.CollectStartupFolders(
            (_, _, name) => ScriptedBytes(name));

        foreach (var record in result.Records)
        {
            Assert.Equal(StartupApproval.ParseState(ScriptedBytes(record.Name)), record.Enabled);
        }

        Assert.DoesNotContain(result.Gaps, g => g.Reason == "ApprovalUnreadable");
    }

    [Fact]
    public void CollectStartupFolders_ApprovalThrows_RecordsKept()
    {
        var result = StartupCollector.CollectStartupFolders(
            (_, _, _) => throw new IOException("locked shelf"));

        Assert.All(result.Records, r => Assert.Null(r.Enabled));
        Assert.True(result.Gaps.Count(g => g.Reason == "ApprovalUnreadable") <= 2);
    }

    // ---- boot line ----

    [Fact]
    public void BootLine_FormatsUptime()
    {
        // 2 days 3 hours in ticks.
        long ticks = (long)TimeSpan.FromHours(51).TotalMilliseconds;
        var boot = BootCollector.Collect(() => ticks);
        string line = BootCollector.RenderLine(boot);

        Assert.StartsWith("Last boot ", line);
        Assert.Contains("uptime 2d 3h", line);
    }

    [Fact]
    public void BootLine_ShortUptime_Minutes()
    {
        long ticks = (long)TimeSpan.FromMinutes(42).TotalMilliseconds;
        string line = BootCollector.RenderLine(BootCollector.Collect(() => ticks));

        Assert.Contains("uptime 42m", line);
    }

    [Fact]
    public void BootLine_CounterFault_Honest()
    {
        string line = BootCollector.RenderLine(
            BootCollector.Collect(() => throw new InvalidOperationException("no counter")));

        Assert.Contains("unknown", line);
        Assert.Contains("InvalidOperationException", line);
    }

    [Fact]
    public void Performance_Collect_CarriesBootLine()
    {
        var snapshot = PerformanceViewModel.Collect([]);

        Assert.StartsWith("Last boot ", snapshot.BootLine);
        var model = new PerformanceViewModel();
        model.Apply(snapshot);
        Assert.Equal(snapshot.BootLine, model.BootLine);
    }

    // ---- the D45 exclusion pin ----

    [Theory]
    [InlineData("disable_startup_item")]
    [InlineData("enable_startup_item")]
    public void StartupTemplates_StaySuspended(string id)
    {
        var template = ActionRegistry.Find(id);
        Assert.NotNull(template);
        Assert.Equal(TemplateStatus.Suspended, template.Status);
    }
}
