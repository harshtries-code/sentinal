using System.Runtime.InteropServices;
using System.Text;

namespace Sentinel.Engine.SystemInventory;

// SetupAPI device enumeration (cfgmgr32): the SAME live source as
// Device Manager and Get-PnpDevice. M3 VM ground truth proved WMI's
// Win32_PnPEntity snapshot misses disconnected/phantom devices
// (code 45) that SetupAPI reports — so problems come from here and
// WMI only donates best-effort display names. Read-only: enumeration
// + status queries, no installs, no state changes.
internal static class DeviceSetupApi
{
    private const uint CM_LOCATE_DEVNODE_NORMAL = 0;
    private const uint CM_LOCATE_DEVNODE_PHANTOM = 1;
    private const int CR_SUCCESS = 0;

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int CM_Get_Device_ID_List_Size(
        out uint pulLen, string? pszFilter, uint ulFlags);

    // Byte buffer, NOT char[]: char[] marshals as ANSI by default and
    // corrupts the wide multi-string. bufferLength is in CHARACTERS;
    // the byte buffer is twice as large.
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int CM_Get_Device_ID_List(
        string? pszFilter, [Out] byte[] buffer, uint bufferLength, uint ulFlags);

    // DEVINST is a 32-bit handle: out uint, NOT out IntPtr (the upper
    // 4 bytes would be garbage and every status lookup would fail).
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int CM_Locate_DevNode(
        out uint pdnDevInst,
        [MarshalAs(UnmanagedType.LPWStr)] string pDeviceID,
        uint ulFlags);

    [DllImport("cfgmgr32.dll", SetLastError = true)]
    private static extern int CM_Get_DevNode_Status(
        out uint pulStatus, out uint pulProblemNumber, uint dnDevInst, uint ulFlags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int CM_Get_DevNode_Registry_Property(
        uint dnDevInst, uint ulProperty, out uint pulRegDataType,
        [Out] byte[] buffer, ref uint pulLength, uint ulFlags);

    // Code 45: "Currently, this hardware device is not connected to the
    // computer." CM_Get_DevNode_Status fails on phantom devnodes by
    // design, so located-but-not-live devices report 45 directly —
    // matching Get-PnpDevice and Device Manager exactly.
    private const uint PROBLEM_DISCONNECTED = 45;
    private const uint CM_DRP_DEVICEDESC = 0;
    private const uint CM_DRP_FRIENDLYNAME = 12;

    // Returns device (id, statusFlags, problemCode, name) rows, or null
    // when SetupAPI itself is unusable (caller falls back with a gap).
    public static List<(string Id, uint Status, uint Problem, string? Name)>? TryEnumerate(out string? fault)
    {
        fault = null;
        try
        {
            // Flags 0 = ALL device instances, including phantoms: problem
            // codes live exactly on the not-present ones.
            if (CM_Get_Device_ID_List_Size(out uint len, null, 0) != CR_SUCCESS || len < 2)
            {
                fault = "IdListSize";
                return null;
            }

            var buffer = new byte[len * 2];
            if (CM_Get_Device_ID_List(null, buffer, len, 0) != CR_SUCCESS)
            {
                fault = "IdList";
                return null;
            }

            var rows = new List<(string, uint, uint, string?)>();
            foreach (var id in SplitMultiString(buffer))
            {
                if (CM_Locate_DevNode(out var node, id, CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS)
                {
                    if (CM_Get_DevNode_Status(out uint status, out uint problem, node, 0) == CR_SUCCESS)
                    {
                        rows.Add((id, status, problem, ReadName(node)));
                    }

                    continue;
                }

                // Not a live node: a phantom (disconnected) device still
                // locates under the PHANTOM flag. Its status call fails
                // by design, so code 45 is reported directly.
                if (CM_Locate_DevNode(out var phantom, id, CM_LOCATE_DEVNODE_PHANTOM) == CR_SUCCESS)
                {
                    rows.Add((id, 0, PROBLEM_DISCONNECTED, ReadName(phantom)));
                }
                // Else vanished mid-enumeration; skip, don't fail.
            }

            return rows;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or SEHException)
        {
            fault = "SetupApi:" + ex.GetType().Name;
            return null;
        }
    }

    private static string? ReadName(uint devInst)
    {
        var buffer = new byte[512];
        uint length = (uint)buffer.Length;
        if (CM_Get_DevNode_Registry_Property(
                devInst, CM_DRP_FRIENDLYNAME, out _, buffer, ref length, 0) == CR_SUCCESS && length > 1)
        {
            return Encoding.Unicode.GetString(buffer, 0, (int)length).TrimEnd('\0');
        }

        length = (uint)buffer.Length;
        if (CM_Get_DevNode_Registry_Property(
                devInst, CM_DRP_DEVICEDESC, out _, buffer, ref length, 0) == CR_SUCCESS && length > 1)
        {
            return Encoding.Unicode.GetString(buffer, 0, (int)length).TrimEnd('\0');
        }

        return null;
    }

    private static IEnumerable<string> SplitMultiString(byte[] buffer)
    {
        string all = Encoding.Unicode.GetString(buffer);
        foreach (var part in all.Split('\0'))
        {
            if (!string.IsNullOrEmpty(part))
            {
                yield return part;
            }
        }
    }
}
