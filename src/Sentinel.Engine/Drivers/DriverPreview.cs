using Sentinel.Engine.Actions;
using Sentinel.Store;

namespace Sentinel.Engine.Drivers;

// One device the user asked about: live state + the resolved ladder
// + already-searched WU candidates. Searches happen before Build
// (the Drivers page runs them); Build only DECIDES.
public sealed record DriverPreviewDevice(
    string DeviceId,
    string DeviceName,
    string? InstalledVersion,
    string? InstalledDate,
    IReadOnlyList<string> HardwareIds,
    LadderResolution Ladder,
    IReadOnlyList<DriverCandidate> WuCandidates);

// One eligible update row: device + the chosen candidate + why.
public sealed record DriverPreviewItem(
    string DeviceId,
    string DeviceName,
    string InstalledVersion,
    DriverCandidate Candidate,
    string WhyEligible,
    string BrokerId);

// One device with no eligible update + its official link-outs.
public sealed record DriverUnsupportedDevice(
    string DeviceId,
    string DeviceName,
    string Reason,
    IReadOnlyList<DriverLinkOut> LinkOuts);

public sealed record DriverLinkOut(string VendorName, string Url);

// The OEM catalogue set, confirmed as ONE set: DCU applies every
// pending update at once, so per-device rows would lie about what
// Confirm does. DeviceIds are the approval targets (aux each).
public sealed record DriverOemSet(
    string VendorId,
    string VendorName,
    IReadOnlyList<string> Titles,
    string Summary,
    IReadOnlyList<string> DeviceIds);

public sealed record DriverPreview(
    IReadOnlyList<DriverPreviewItem> Included,
    IReadOnlyList<DriverUnsupportedDevice> Unsupported,
    DriverOemSet? OemSet,
    string? OemNote,
    string? RefusedReason,
    DateTime PreviewedUtc,
    bool IsElevated);

// One rollback row: the bad live version + the store target.
public sealed record DriverRollbackItem(
    string DeviceId,
    string DeviceName,
    string BadVersion,
    string PreviousVersion,
    string TargetInf,
    string BadSource,
    string BrokerId);

public sealed record DriverRollbackRequest(
    string DeviceId,
    string DeviceName,
    string? HardwareId,
    string? LiveVersion);

public sealed record DriverRollbackPreview(
    IReadOnlyList<DriverRollbackItem> Included,
    IReadOnlyList<DriverUnsupportedDevice> Unsupported,
    string? RefusedReason,
    DateTime PreviewedUtc,
    bool IsElevated);

// D43: driver confirm-sheet input. Pure decision logic over
// already-collected evidence — no live calls, no guessing.
//   - Update: first ELIGIBLE WU candidate per device wins (hardware
//     + signature + newer + unblocked, via DriverMatching).
//   - OEM set precedence: the catalogue set is offered ONLY when NO
//     device has a WU row — a machine-wide apply is never bundled
//     with per-device updates. Otherwise it is noted, not included.
//   - Unsupported devices carry the honest reason + official
//     link-outs (never a guessed vendor).
//   - Rollback: the most recent on-record older version + a store
//     package matched by version (date unknown → date ignored by
//     D41 rule; ambiguous → refused, never guessed).
public static class DriverPreviewBuilder
{
    public static DriverPreview Build(
        IReadOnlyList<DriverPreviewDevice> devices,
        OemScanSet? oemScan,
        IReadOnlySet<string> blockedKeys,
        bool isElevated)
    {
        var included = new List<DriverPreviewItem>();
        var unsupported = new List<DriverUnsupportedDevice>();

        foreach (var device in devices)
        {
            if (string.IsNullOrWhiteSpace(device.InstalledVersion))
            {
                unsupported.Add(new DriverUnsupportedDevice(
                    device.DeviceId, device.DeviceName,
                    "The installed driver version could not be observed — " +
                    "updating without a known rollback point is refused.",
                    LinkOuts(device.Ladder)));
                continue;
            }

            DriverPreviewItem? pick = null;
            string? lastReason = null;
            foreach (var candidate in device.WuCandidates)
            {
                var verdict = DriverMatching.CheckEligible(
                    candidate, device.InstalledVersion, device.HardwareIds, blockedKeys);
                if (verdict.Eligible)
                {
                    pick = new DriverPreviewItem(
                        device.DeviceId, device.DeviceName, device.InstalledVersion,
                        candidate, verdict.Reason, "dev:" + device.DeviceId);
                    break;
                }

                lastReason = verdict.Reason;
            }

            if (pick is not null)
            {
                included.Add(pick);
                continue;
            }

            unsupported.Add(new DriverUnsupportedDevice(
                device.DeviceId, device.DeviceName,
                device.WuCandidates.Count == 0
                    ? "Windows Update offers no driver for this device right now."
                    : $"No eligible Windows Update candidate ({device.WuCandidates.Count} seen): {lastReason}",
                LinkOuts(device.Ladder)));
        }

        DriverOemSet? oemSet = null;
        string? oemNote = null;
        var oemStep = devices
            .SelectMany(d => d.Ladder.Steps)
            .FirstOrDefault(s => s.Source == DriverSource.OemCatalogue && s.VendorId is not null);
        if (oemStep is not null && oemScan is not null && oemScan.UpdateTitles.Count > 0)
        {
            var vendor = OemVendors.Find(oemStep.VendorId!);
            string vendorName = vendor?.DisplayName ?? oemStep.VendorId!;
            if (included.Count == 0)
            {
                oemSet = new DriverOemSet(
                    oemStep.VendorId!, vendorName, oemScan.UpdateTitles, oemScan.RawSummary,
                    devices.Select(d => d.DeviceId).ToList());
            }
            else
            {
                oemNote = $"The {vendorName} catalogue also lists " +
                    $"{oemScan.UpdateTitles.Count} update(s) — confirm the Windows Update " +
                    "rows first; the catalogue applies as a machine-wide set, never bundled " +
                    "with per-device updates.";
            }
        }

        string? refused = null;
        if (!isElevated)
        {
            refused = ElevationPolicy.RelaunchReason;
        }
        else if (included.Count == 0 && oemSet is null)
        {
            refused = devices.Count == 0
                ? "No devices selected."
                : "No eligible updates for the selected device(s) — see the reasons above.";
        }

        return new DriverPreview(included, unsupported, oemSet, oemNote, refused,
            DateTime.UtcNow, isElevated);
    }

    public static DriverRollbackPreview BuildRollback(
        IReadOnlyList<DriverRollbackRequest> requests,
        Func<string, IReadOnlyList<DeviceHistoryRow>> historyReader,
        IReadOnlyList<StorePackage> store,
        bool isElevated)
    {
        var included = new List<DriverRollbackItem>();
        var unsupported = new List<DriverUnsupportedDevice>();

        foreach (var request in requests)
        {
            if (string.IsNullOrWhiteSpace(request.LiveVersion))
            {
                unsupported.Add(new DriverUnsupportedDevice(
                    request.DeviceId, request.DeviceName,
                    "The live driver version could not be observed — nothing to roll back from.",
                    []));
                continue;
            }

            IReadOnlyList<DeviceHistoryRow> history;
            try
            {
                history = historyReader(request.DeviceId);
            }
            catch (Exception ex)
            {
                unsupported.Add(new DriverUnsupportedDevice(
                    request.DeviceId, request.DeviceName,
                    $"Device history could not be read ({ex.GetType().Name}) — " +
                    "rollback needs an on-record earlier version.",
                    []));
                continue;
            }

            // Latest-first: skip rows still on the live version; the
            // first older version is the rollback target.
            string? previous = null;
            foreach (var row in history)
            {
                if (string.IsNullOrWhiteSpace(row.DriverVersion))
                {
                    continue;
                }

                if (DriverMatching.CompareVersions(row.DriverVersion, request.LiveVersion, out _) == 0)
                {
                    continue;
                }

                previous = row.DriverVersion;
                break;
            }

            if (previous is null)
            {
                unsupported.Add(new DriverUnsupportedDevice(
                    request.DeviceId, request.DeviceName,
                    "No earlier driver version is on record for this device — " +
                    "Sentinel only rolls back to a version it has actually seen.",
                    []));
                continue;
            }

            var installed = new SystemInventory.DriverRecord(
                request.DeviceName, previous, null, null, null, request.HardwareId);
            var (identity, failure) = DriverIdentityCapture.MatchStorePackage(
                request.DeviceId, request.HardwareId, installed, store);
            if (identity is null)
            {
                unsupported.Add(new DriverUnsupportedDevice(
                    request.DeviceId, request.DeviceName,
                    $"Earlier version {previous} is on record, but {FirstSentence(failure)}",
                    []));
                continue;
            }

            included.Add(new DriverRollbackItem(
                request.DeviceId, request.DeviceName, request.LiveVersion, previous,
                identity.PublishedInf, "unknown", "rb:" + request.DeviceId));
        }

        string? refused = null;
        if (!isElevated)
        {
            refused = ElevationPolicy.RelaunchReason;
        }
        else if (included.Count == 0)
        {
            refused = requests.Count == 0
                ? "No devices selected."
                : "No device has a rollback target — see the reasons above.";
        }

        return new DriverRollbackPreview(included, unsupported, refused,
            DateTime.UtcNow, isElevated);
    }

    private static IReadOnlyList<DriverLinkOut> LinkOuts(LadderResolution ladder)
    {
        var links = new List<DriverLinkOut>();
        foreach (var step in ladder.Steps)
        {
            if (step.Source != DriverSource.VendorLinkOut || step.VendorId is null)
            {
                continue;
            }

            var vendor = OemVendors.Find(step.VendorId);
            if (vendor is null)
            {
                continue;
            }

            if (links.All(l => l.Url != vendor.SupportUrl))
            {
                links.Add(new DriverLinkOut(vendor.DisplayName, vendor.SupportUrl));
            }
        }

        return links;
    }

    private static string FirstSentence(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return "no rollback target is available.";
        }

        // Identity failures end "— refusing ...": keep the cause,
        // drop the refusal tail (the sheet states that itself).
        int dash = text.IndexOf(" — ", StringComparison.Ordinal);
        string head = (dash >= 0 ? text.Substring(0, dash) : text).Trim();
        return char.ToLowerInvariant(head[0]) + head.Substring(1) + ".";
    }
}
