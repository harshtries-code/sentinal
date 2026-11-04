using System.Runtime.InteropServices;
using Sentinel.Engine.Scan;

namespace Sentinel.App.Services;

internal static class LiveTelemetry
{
    internal static string BatteryLine(PowerState power)
    {
        if (power.HasBattery == false)
        {
            return "No battery device";
        }

        return power.BatteryPercent is >= 0 and <= 100
            ? $"Battery {power.BatteryPercent}%"
            : "Battery charge unavailable";
    }

    internal static string ReadSystemMemory()
    {
        var memory = new MemoryStatus { Length = (uint)Marshal.SizeOf<MemoryStatus>() };
        if (!GlobalMemoryStatusEx(ref memory) || memory.TotalPhysical == 0
            || memory.AvailablePhysical > memory.TotalPhysical)
        {
            return "PC memory unavailable";
        }

        const double bytesPerGiB = 1024.0 * 1024 * 1024;
        double used = (memory.TotalPhysical - memory.AvailablePhysical) / bytesPerGiB;
        return $"PC memory: {used:F1} / {memory.TotalPhysical / bytesPerGiB:F1} GB in use";
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatus
    {
        public uint Length;
        public uint Load;
        public ulong TotalPhysical;
        public ulong AvailablePhysical;
        public ulong TotalPageFile;
        public ulong AvailablePageFile;
        public ulong TotalVirtual;
        public ulong AvailableVirtual;
        public ulong AvailableExtendedVirtual;
    }

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatus memory);
}
