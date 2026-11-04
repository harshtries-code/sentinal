using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Sentinel.Engine.Drivers;

// System-restore client seam. Production calls srclient.dll (LIVE
// ONLY — the VM battery); tests inject fakes. A restore point is a
// precondition, never a guarantee: D41 refuses before mutation when
// one cannot be created, and says so.
public interface ISrClient
{
    // Opens a restore-point sequence. Success returns the sequence
    // number; failure returns null + the honest error.
    (long? Sequence, string? Error) Begin(string description);

    // Closes the sequence. Returns null on success, else the error
    // (the restore point may still be usable — the caller says so).
    string? End(long sequence);
}

public sealed record RestoreCapability(bool Capable, string Reason);

public static class RestorePointManager
{
    private const string SrKey = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore";

    // Read-only pre-check: DisableSR == 1 means System Protection is
    // off and no restore point can be created. Missing/0 means on.
    // Unknown (read failure) fails CLOSED — refusing without a
    // backup is always safer than assuming one.
    public static RestoreCapability CheckCapability(Func<int?>? disableSrReader = null)
    {
        int? value;
        try
        {
            value = disableSrReader?.Invoke() ?? ReadDisableSr();
        }
        catch (Exception ex)
        {
            return new RestoreCapability(false,
                $"System Protection state could not be determined ({ex.GetType().Name}) — " +
                "refusing to change drivers without a verified backup.");
        }

        if (value == 1)
        {
            return new RestoreCapability(false,
                "System Protection is turned off, so no restore point can be created. " +
                "Turn it on for the system drive, then retry — Sentinel never changes drivers without one.");
        }

        return new RestoreCapability(true,
            "System Protection is on — a restore point will be created before any driver change.");
    }

    public static int? ReadDisableSr()
    {
        try
        {
            object? value = Registry.GetValue(SrKey, "DisableSR", null);
            return value switch
            {
                null => null,
                int i => i,
                long l => (int)l,
                _ => null,
            };
        }
        catch
        {
            return null;
        }
    }

    public static (long? Sequence, string? Error) Begin(ISrClient client, string description)
    {
        try
        {
            return client.Begin(description);
        }
        catch (Exception ex)
        {
            return (null, $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    public static string? End(ISrClient client, long sequence)
    {
        try
        {
            return client.End(sequence);
        }
        catch (Exception ex)
        {
            return $"{ex.GetType().Name}: {ex.Message}";
        }
    }
}

// LIVE srclient.dll wrapper. NEVER invoked on the host — every host
// test uses a fake ISrClient, and live creation runs in the VM
// battery only (D41 vm leg). DEVICE_DRIVER_INSTALL type + BEGIN/END
// pair per the SRSetRestorePoint contract.
public sealed class SrClient : ISrClient
{
    private const int BeginSystemChange = 100;
    private const int EndSystemChange = 101;
    private const int DeviceDriverInstall = 10;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RestorePointInfo
    {
        public int dwEventType;
        public int dwRestorePtType;
        public long llSequenceNumber;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szDescription;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StateMgrStatus
    {
        public int nStatus;
        public long llSequenceNumber;
    }

    [DllImport("srclient.dll", CharSet = CharSet.Unicode)]
    private static extern bool SRSetRestorePointW(
        ref RestorePointInfo pRestorePtSpec, out StateMgrStatus pSMgrStatus);

    public (long? Sequence, string? Error) Begin(string description)
    {
        var info = new RestorePointInfo
        {
            dwEventType = BeginSystemChange,
            dwRestorePtType = DeviceDriverInstall,
            llSequenceNumber = 0,
            szDescription = description.Length > 255 ? description.Substring(0, 255) : description,
        };
        bool ok = SRSetRestorePointW(ref info, out var status);
        if (!ok)
        {
            return (null, $"SRSetRestorePoint BEGIN failed (status {status.nStatus}, Win32 {Marshal.GetLastWin32Error()}).");
        }

        return (status.llSequenceNumber, null);
    }

    public string? End(long sequence)
    {
        var info = new RestorePointInfo
        {
            dwEventType = EndSystemChange,
            dwRestorePtType = DeviceDriverInstall,
            llSequenceNumber = sequence,
            szDescription = string.Empty,
        };
        bool ok = SRSetRestorePointW(ref info, out var status);
        return ok ? null : $"SRSetRestorePoint END failed (status {status.nStatus}). The BEGIN point may still be usable.";
    }
}
