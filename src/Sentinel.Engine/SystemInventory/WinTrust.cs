using System.Runtime.InteropServices;

namespace Sentinel.Engine.SystemInventory;

// WinVerifyTrust file check (wintrust.dll): the SAME source as
// Get-AuthenticodeSignature and Explorer's signature tab. Embedded
// PKCS#7 parsing alone misses catalog-signed system binaries
// (notepad.exe, powershell.exe verify here but carry no embedded
// blob) — trust MUST go through the catalog-aware verifier.
// Read-only: no UI, no revocation network (WTD_REVOKE_NONE), no
// state changes. A trust failure is "not verified", never malware.
internal static class WinTrust
{
    private static readonly Guid ActionGenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile; // WINTRUST_FILE_INFO*, union arm for WTD_CHOICE_FILE.
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public string? pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint WinVerifyTrust(
        IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, IntPtr pWVTData);

    /// <summary>
    /// Verifies file trust through the catalog-aware provider.
    /// Returns (trusted, win32/error code): 0 means verified.
    /// </summary>
    public static (bool Trusted, uint Code) VerifyFileTrust(string path)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = path,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };
        var data = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = WTD_CHOICE_FILE,
            dwStateAction = WTD_STATEACTION_VERIFY,
        };

        IntPtr filePtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        IntPtr dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
        try
        {
            Marshal.StructureToPtr(fileInfo, filePtr, false);
            data.pFile = filePtr;
            Marshal.StructureToPtr(data, dataPtr, false);

            uint code = WinVerifyTrust(IntPtr.Zero, ActionGenericVerifyV2, dataPtr);

            data.dwStateAction = WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(data, dataPtr, true);
            WinVerifyTrust(IntPtr.Zero, ActionGenericVerifyV2, dataPtr);

            return (code == 0, code);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or SEHException)
        {
            return (false, 0x80004005); // Verifier itself unusable.
        }
        finally
        {
            Marshal.DestroyStructure<WINTRUST_DATA>(dataPtr);
            Marshal.DestroyStructure<WINTRUST_FILE_INFO>(filePtr);
            Marshal.FreeHGlobal(dataPtr);
            Marshal.FreeHGlobal(filePtr);
        }
    }
}
