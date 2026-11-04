using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Sentinel.Engine.SystemInventory;

// Process parent map via the ToolHelp snapshot (one syscall for
// the whole table — far cheaper than per-process WMI). Windows
// only; anywhere else (or on any failure) the map is empty and
// parents read unknown. Read-only: a snapshot handle, closed.
public static class ProcessParentMap
{
    public static Dictionary<int, (int ParentId, string Exe)> Collect()
    {
        var map = new Dictionary<int, (int, string)>();
        if (Environment.OSVersion.Platform != PlatformID.Win32NT)
        {
            return map;
        }

        try
        {
            CollectLive(map);
        }
        catch
        {
            // Best effort: callers treat a thin map as unknown
            // parents, never as no parents.
        }

        return map;
    }

    [SupportedOSPlatform("windows")]
    private static void CollectLive(Dictionary<int, (int ParentId, string Exe)> map)
    {
        IntPtr snap = Native.CreateToolhelp32Snapshot(0x00000002 /* TH32CS_SNAPPROCESS */, 0);
        if (snap == IntPtr.Zero || snap == new IntPtr(-1))
        {
            return;
        }

        try
        {
            var entry = new Native.ProcessEntry32 { dwSize = (uint)Marshal.SizeOf<Native.ProcessEntry32>() };
            if (!Native.Process32First(snap, ref entry))
            {
                return;
            }

            do
            {
                map[(int)entry.th32ProcessID] = ((int)entry.th32ParentProcessID, entry.szExeFile ?? string.Empty);
            }
            while (Native.Process32Next(snap, ref entry));
        }
        finally
        {
            Native.CloseHandle(snap);
        }
    }

    private static class Native
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool Process32First(IntPtr hSnapshot, ref ProcessEntry32 lppe);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool Process32Next(IntPtr hSnapshot, ref ProcessEntry32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct ProcessEntry32
        {
            internal uint dwSize;
            internal uint cntUsage;
            internal uint th32ProcessID;
            internal IntPtr th32DefaultHeapID;
            internal uint th32ModuleID;
            internal uint cntThreads;
            internal uint th32ParentProcessID;
            internal int pcPriClassBase;
            internal uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            internal string szExeFile;
        }
    }
}

// READ-ONLY TCP inventory with owning PIDs (endpoint metadata
// only — no packet content exists at this layer). Bounded at
// 2000 rows; the tab joins rows to the selected process.
public static class NetworkCollector
{
    public const int MaxConnections = 2000;

    public static CollectionResult<TcpConnectionRecord> Collect()
    {
        const string scope = "TCP connections (endpoints only)";
        var observed = DateTime.UtcNow;
        if (Environment.OSVersion.Platform != PlatformID.Win32NT)
        {
            return CollectionResult<TcpConnectionRecord>.Fail(scope, "WindowsOnly");
        }

        List<TcpConnectionRecord> rows;
        try
        {
            rows = CollectLive();
        }
        catch (Exception ex)
        {
            return CollectionResult<TcpConnectionRecord>.Fail(
                scope, ex.GetType().Name, Trim(ex.Message));
        }

        bool truncated = rows.Count > MaxConnections;
        if (truncated)
        {
            rows.RemoveRange(MaxConnections, rows.Count - MaxConnections);
        }

        var gaps = new List<CollectionGap>();
        if (truncated)
        {
            gaps.Add(new CollectionGap(scope, "Truncated", $"kept first {MaxConnections}"));
        }

        var status = gaps.Count == 0 ? CollectionStatus.Success : CollectionStatus.Partial;
        return new CollectionResult<TcpConnectionRecord>(
            status, rows, scope, observed, gaps, truncated);
    }

    [SupportedOSPlatform("windows")]
    private static List<TcpConnectionRecord> CollectLive()
    {
        var rows = new List<TcpConnectionRecord>();
        foreach (var connection in IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections())
        {
            // No PID at this layer (see ExtendedTcpTable below for
            // the owning-PID join); rows still carry endpoints.
            rows.Add(new TcpConnectionRecord(0,
                connection.LocalEndPoint?.ToString() ?? "?",
                connection.RemoteEndPoint?.ToString() ?? "?",
                connection.State.ToString()));
        }

        // Owning-PID overlay: same endpoints, PID-attached.
        var owners = ExtendedTcpTable.Collect();
        if (owners.Count > 0)
        {
            var byEndpoints = new Dictionary<(string Local, string Remote, string State), int>();
            foreach (var owner in owners)
            {
                byEndpoints.TryAdd((owner.Local, owner.Remote, owner.State), owner.Pid);
            }

            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                if (byEndpoints.TryGetValue((row.Local, row.Remote, row.State), out int pid))
                {
                    rows[i] = row with { Pid = pid };
                }
            }
        }

        return rows;
    }

    private static string Trim(string s)
    {
        s = (s ?? string.Empty).Trim().ReplaceLineEndings(" ");
        return s.Length <= 200 ? s : s[..200];
    }
}

// GetExtendedTcpTable (TCP_TABLE_OWNER_PID_ALL): the managed
// TcpConnectionInformation has no PID, so the owner map comes
// from iphlpapi and joins by endpoint triple. IPv4 + IPv6.
internal static class ExtendedTcpTable
{
    internal sealed record OwnerRow(int Pid, string Local, string Remote, string State);

    internal static List<OwnerRow> Collect()
    {
        var rows = new List<OwnerRow>();
        CollectFamily(rows, AddressFamilyV4: true);
        CollectFamily(rows, AddressFamilyV4: false);
        return rows;
    }

    private static void CollectFamily(List<OwnerRow> rows, bool AddressFamilyV4)
    {
        int af = AddressFamilyV4 ? 2 /* AF_INET */ : 23 /* AF_INET6 */;
        int size = 0;
        Native.GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, 5 /* OWNER_PID_ALL */, 0);
        if (size <= 0 || size > 256 * 1024 * 1024)
        {
            return;
        }

        IntPtr table = Marshal.AllocHGlobal(size);
        try
        {
            if (Native.GetExtendedTcpTable(table, ref size, false, af, 5, 0) != 0)
            {
                return;
            }

            int count = Marshal.ReadInt32(table);
            if (count < 0 || count > 1_000_000)
            {
                return;
            }

            IntPtr rowPtr = table + 4;
            int stride = AddressFamilyV4 ? 24 : 56;
            for (int i = 0; i < count; i++)
            {
                try
                {
                    rows.Add(ReadRow(rowPtr, AddressFamilyV4));
                }
                catch
                {
                    // One corrupt row never sinks the table.
                }

                rowPtr += stride;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(table);
        }
    }

    private static OwnerRow ReadRow(IntPtr rowPtr, bool v4)
    {
        if (v4)
        {
            uint state = (uint)Marshal.ReadInt32(rowPtr, 0);
            string local = Endpoint(Marshal.ReadInt32(rowPtr, 4), Marshal.ReadInt32(rowPtr, 8));
            string remote = Endpoint(Marshal.ReadInt32(rowPtr, 12), Marshal.ReadInt32(rowPtr, 16));
            int pid = Marshal.ReadInt32(rowPtr, 20);
            return new OwnerRow(pid, local, remote, TcpStateName(state));
        }

        // MIB_TCP6ROW_OWNER_PID: dwState 0, dwLocalScopeId 4,
        // ucLocalAddr 8..24, dwLocalPort 24, ucRemoteAddr 28..44,
        // dwRemotePort 44, dwOwningPid 48 (stride 56).
        byte[] localBytes = new byte[16];
        byte[] remoteBytes = new byte[16];
        Marshal.Copy(rowPtr + 8, localBytes, 0, 16);
        Marshal.Copy(rowPtr + 28, remoteBytes, 0, 16);
        int localScope = Marshal.ReadInt32(rowPtr, 4);
        string local6 = Endpoint6(localBytes, localScope, Marshal.ReadInt32(rowPtr, 24));
        string remote6 = Endpoint6(remoteBytes, 0, Marshal.ReadInt32(rowPtr, 44));
        uint state6 = (uint)Marshal.ReadInt32(rowPtr, 0);
        int pid6 = Marshal.ReadInt32(rowPtr, 48);
        return new OwnerRow(pid6, local6, remote6, TcpStateName(state6));
    }

    // MIB_TCPROW_OWNER_PID offsets (DWORDs): dwState 0, dwLocalAddr
    // 4, dwLocalPort 8, dwRemoteAddr 12, dwRemotePort 16,
    // dwOwningPid 20. Ports are network-order in the low 16 bits.
    private static string Endpoint(int addr, int portNetwork)
    {
        var ip = new System.Net.IPAddress((uint)addr);
        int port = System.Net.IPAddress.NetworkToHostOrder((short)(portNetwork & 0xFFFF)) & 0xFFFF;
        return $"{ip}:{port}";
    }

    // MIB_TCP6ROW_OWNER_PID: dwState 0, dwLocalScopeId 4,
    // ucLocalAddr 8..24, dwLocalPort 24, ucRemoteAddr 28..44,
    // dwRemotePort 44, dwOwningPid 48. (Stride 56 with padding.)
    private static string Endpoint6(byte[] addr, int scope, int portNetwork)
    {
        var ip = new System.Net.IPAddress(addr, scope);
        int port = System.Net.IPAddress.NetworkToHostOrder((short)(portNetwork & 0xFFFF)) & 0xFFFF;
        return $"[{ip}]:{port}";
    }

    private static string TcpStateName(uint state) => state switch
    {
        1 => "Closed",
        2 => "Listen",
        3 => "SynSent",
        4 => "SynReceived",
        5 => "Established",
        6 => "FinWait1",
        7 => "FinWait2",
        8 => "CloseWait",
        9 => "Closing",
        10 => "LastAck",
        11 => "TimeWait",
        12 => "DeleteTcb",
        _ => $"Unknown({state})",
    };

    private static class Native
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        internal static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable, ref int dwOutBufLen, bool sort,
            int ipVersion, int tblClass, uint reserved);
    }
}
