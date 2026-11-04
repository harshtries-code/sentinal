using System.Management;
using System.Runtime.InteropServices;

namespace Sentinel.Engine.SystemInventory;

// READ-ONLY: disk → partition → volume topology from the Storage
// CIM namespace (the same data behind Get-Disk/Get-Partition/
// Get-Volume). Answers "is the disk visible, which partitions and
// volumes exist, how do they join" — the missing-partition story's
// first question. Nothing is initialized, mounted, or repaired.
public static class DiskTopologyCollector
{
    private const string Scope = "MSFT_Disk + MSFT_Partition + MSFT_Volume (storage namespace)";
    private const string Namespace = @"ROOT\Microsoft\Windows\Storage";

    public static CollectionResult<DiskTopologyRecord> Collect()
    {
        var observed = DateTime.UtcNow;
        var gaps = new List<CollectionGap>();
        string scope = Scope;
        try
        {
            var volumes = ReadVolumes(gaps);
            var volumesByLetter = volumes
                .Where(v => !string.IsNullOrEmpty(v.DriveLetter))
                .GroupBy(v => v.DriveLetter!, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
            var partitionsByDisk = ReadPartitions(gaps);
            // P24 (R06.6): disk → PnP device identity. Win32_DiskDrive
            // Index shares MSFT_Disk Number numbering; a failed join
            // query leaves IDs null (stated), never invented.
            var deviceIds = ReadDiskDeviceIds(gaps);
            var disks = new List<DiskTopologyRecord>();

            using var searcher = new ManagementObjectSearcher(
                Namespace,
                "SELECT Number, FriendlyName, BusType, HealthStatus, PartitionStyle, Size, IsBoot FROM MSFT_Disk");
            foreach (var obj in searcher.Get())
            {
                using (obj)
                {
                    uint number = ToUInt(obj, "Number") ?? uint.MaxValue;
                    var parts = new List<PartitionRecord>();
                    if (partitionsByDisk.TryGetValue(number, out var rows))
                    {
                        foreach (var row in rows.OrderBy(r => r.PartitionNumber))
                        {
                            // A letter matching no volume means offline or
                            // unrecognized filesystem: Volume stays null,
                            // reported — never invented.
                            volumesByLetter.TryGetValue(row.DriveLetter ?? string.Empty, out var vol);
                            if (row.DriveLetter is null)
                            {
                                vol = null;
                            }

                            parts.Add(new PartitionRecord(
                                row.PartitionNumber, row.SizeBytes, row.DriveLetter,
                                row.Type, row.IsBoot, row.IsSystem, vol));
                        }
                    }

                    deviceIds.TryGetValue(number, out string? pnpId);
                    disks.Add(new DiskTopologyRecord(
                        DiskNumber: number,
                        Name: ToStr(obj, "FriendlyName") ?? "(disk)",
                        BusType: BusTypeName(ToUInt(obj, "BusType")),
                        HealthStatus: HealthName(ToUInt(obj, "HealthStatus")),
                        PartitionStyle: PartitionStyleName(ToUInt(obj, "PartitionStyle")),
                        SizeBytes: ToLong(obj, "Size"),
                        IsBoot: ToBool(obj, "IsBoot"),
                        Partitions: parts,
                        PnpDeviceId: pnpId));
                }
            }

            // Calibrated gaps (M3 VM ground truth: EFI + recovery volumes
            // are letterless on EVERY healthy machine, so letterlessness
            // alone is not a gap):
            // - a LETTERED volume no partition claimed = real inconsistency.
            // - a letterless BASIC-DATA partition = the missing-drive
            //   signal (present but unmounted); system/boot/hidden ones
            //   are normal and counted in the scope note instead.
            var claimed = new HashSet<string>(
                disks.SelectMany(d => d.Partitions)
                    .Where(p => p.Volume is not null)
                    .Select(p => p.Volume!.Path),
                StringComparer.OrdinalIgnoreCase);
            int letteredOrphans = volumes
                .Where(v => !string.IsNullOrEmpty(v.DriveLetter))
                .Select(v => v.Path)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count(p => !claimed.Contains(p));
            if (letteredOrphans > 0)
            {
                gaps.Add(new CollectionGap(scope, "OrphanVolumes", letteredOrphans.ToString()));
            }

            var unmountedData = disks
                .SelectMany(d => d.Partitions.Select(p => (Disk: d.DiskNumber, Part: p)))
                .Where(x => x.Part.DriveLetter is null && x.Part.Volume is null
                    && x.Part.Type == "Basic data")
                .Select(x => $"{x.Disk}:{x.Part.PartitionNumber}")
                .ToList();
            if (unmountedData.Count > 0)
            {
                gaps.Add(new CollectionGap(
                    scope, "UnmountedDataPartition", string.Join(",", unmountedData)));
            }

            int letterless = volumes.Count(v => string.IsNullOrEmpty(v.DriveLetter));
            if (letterless > 0)
            {
                scope += $" ({letterless} unmounted volumes)";
            }

            if (disks.Count == 0)
            {
                gaps.Add(new CollectionGap(scope, "NoDisksEnumerated", null));
            }

            return new CollectionResult<DiskTopologyRecord>(
                gaps.Count == 0 ? CollectionStatus.Success : CollectionStatus.Partial,
                disks.OrderBy(d => d.DiskNumber).ToList(),
                scope, observed, gaps, false);
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or COMException)
        {
            return CollectionResult<DiskTopologyRecord>.Fail(Scope, "StorageQueryFailed", ex.GetType().Name);
        }
    }

    private static List<VolumeRecord> ReadVolumes(List<CollectionGap> gaps)
    {
        // ALL volumes, including letterless ones: an unmounted but
        // present volume is exactly what a missing-drive story needs.
        var volumes = new List<VolumeRecord>();
        using var searcher = new ManagementObjectSearcher(
            Namespace,
            "SELECT DriveLetter, FileSystem, FileSystemLabel, Size, SizeRemaining, " +
            "HealthStatus, DriveType, Path FROM MSFT_Volume");
        foreach (var obj in searcher.Get())
        {
            using (obj)
            {
                string path = ToStr(obj, "Path") ?? string.Empty;
                if (string.IsNullOrEmpty(path))
                {
                    gaps.Add(new CollectionGap("MSFT_Volume", "VolumeWithoutPath", null));
                    continue;
                }

                volumes.Add(new VolumeRecord(
                    DriveLetter: DriveLetterName(obj, "DriveLetter"),
                    FileSystem: ToStr(obj, "FileSystem"),
                    Label: ToStr(obj, "FileSystemLabel"),
                    SizeBytes: ToLong(obj, "Size"),
                    SizeRemainingBytes: ToLong(obj, "SizeRemaining"),
                    HealthStatus: HealthName(ToUInt(obj, "HealthStatus")),
                    Path: path));
            }
        }

        return volumes;
    }

    private sealed record PartitionRow(
        uint DiskNumber,
        uint PartitionNumber,
        long? SizeBytes,
        string? DriveLetter,
        string? Type,
        bool IsBoot,
        bool IsSystem);

    private static Dictionary<uint, string> ReadDiskDeviceIds(List<CollectionGap> gaps)
    {
        var byIndex = new Dictionary<uint, string>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Index, PNPDeviceID FROM Win32_DiskDrive");
            foreach (var obj in searcher.Get())
            {
                using (obj)
                {
                    uint? index = ToUInt(obj, "Index");
                    string? id = ToStr(obj, "PNPDeviceID");
                    if (index is not null && !string.IsNullOrEmpty(id))
                    {
                        byIndex.TryAdd(index.Value, id);
                    }
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or COMException)
        {
            gaps.Add(new CollectionGap(
                "Win32_DiskDrive", "DiskDeviceJoinFailed", ex.GetType().Name));
        }

        return byIndex;
    }

    private static Dictionary<uint, List<PartitionRow>> ReadPartitions(List<CollectionGap> gaps)
    {
        _ = gaps;
        var byDisk = new Dictionary<uint, List<PartitionRow>>();
        // NOTE: MSFT_Partition has no plain "Type" property (verified:
        // the query fails with "Invalid property"). The record's Type
        // is a derived label from role flags, stated as such.
        using var searcher = new ManagementObjectSearcher(
            Namespace,
            "SELECT DiskNumber, PartitionNumber, Size, DriveLetter, IsBoot, IsSystem, IsHidden FROM MSFT_Partition");
        foreach (var obj in searcher.Get())
        {
            using (obj)
            {
                uint disk = ToUInt(obj, "DiskNumber") ?? uint.MaxValue;
                if (!byDisk.TryGetValue(disk, out var rows))
                {
                    rows = new List<PartitionRow>();
                    byDisk[disk] = rows;
                }

                bool isBoot = ToBool(obj, "IsBoot");
                bool isSystem = ToBool(obj, "IsSystem");
                rows.Add(new PartitionRow(
                    disk,
                    ToUInt(obj, "PartitionNumber") ?? 0,
                    ToLong(obj, "Size"),
                    DriveLetterName(obj, "DriveLetter"),
                    isSystem ? "System" : isBoot ? "Boot" : ToBool(obj, "IsHidden") ? "Hidden" : "Basic data",
                    isBoot,
                    isSystem));
            }
        }

        return byDisk;
    }

    private static string? ToStr(ManagementBaseObject obj, string name)
    {
        try
        {
            var value = obj[name]?.ToString();
            return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
        }
        catch
        {
            return null;
        }
    }

    private static uint? ToUInt(ManagementBaseObject obj, string name)
    {
        try
        {
            var value = obj[name];
            return value is null ? null : Convert.ToUInt32(value);
        }
        catch
        {
            return null;
        }
    }

    private static long? ToLong(ManagementBaseObject obj, string name)
    {
        try
        {
            var value = obj[name];
            return value is null ? null : Convert.ToInt64(value);
        }
        catch
        {
            return null;
        }
    }

    private static bool ToBool(ManagementBaseObject obj, string name)
    {
        try
        {
            return Convert.ToBoolean(obj[name] ?? false);
        }
        catch
        {
            return false;
        }
    }

    // DriveLetter arrives as a char code (0 = none).
    private static string? DriveLetterName(ManagementBaseObject obj, string name)
    {
        try
        {
            var value = obj[name];
            if (value is null)
            {
                return null;
            }

            int code = Convert.ToInt32(value);
            if (code == 0)
            {
                return null;
            }

            char c = Convert.ToChar(code);
            return char.IsLetter(c) ? c.ToString() : null;
        }
        catch
        {
            return null;
        }
    }

    private static string BusTypeName(uint? code)
    {
        return code switch
        {
            1 => "SCSI",
            7 => "USB",
            8 => "RAID",
            9 => "iSCSI",
            11 => "SATA",
            14 => "Virtual",
            15 => "FileBackedVirtual",
            16 => "StorageSpaces",
            17 => "NVMe",
            _ => "Unknown",
        };
    }

    private static string PartitionStyleName(uint? code)
    {
        return code switch
        {
            1 => "MBR",
            2 => "GPT",
            _ => "Unknown",
        };
    }

    private static string HealthName(uint? code)
    {
        return code switch
        {
            0 => "Healthy",
            1 => "Warning",
            2 => "Unhealthy",
            _ => "Unknown",
        };
    }
}
