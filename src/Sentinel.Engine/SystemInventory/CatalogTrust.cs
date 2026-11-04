using System.Runtime.InteropServices;

namespace Sentinel.Engine.SystemInventory;

// Security-catalog membership (crypt32 CryptCATAdmin*): the path
// Get-AuthenticodeSignature takes when a file carries no embedded
// PKCS#7. WinVerifyTrust alone reports TRUST_E_NOSIGNATURE for
// catalog-signed system files (cmd.exe, notepad.exe verify here
// but are Valid per Get-AuthenticodeSignature), so trust =
// embedded-verify OR catalog-membership-with-verified-catalog.
// Read-only: hash + catalog lookup, no installs, no network.
internal static class CatalogTrust
{
    private const uint CALG_SHA_256 = 0x0000800c;
    private const uint CALG_SHA1 = 0x00008004;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(
        out IntPtr phCatAdmin, IntPtr pgSubsystem, IntPtr pwszHashAlgorithm,
        IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash,
        byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin, byte[] pbHash, uint cbHash,
        uint dwFlags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(
        IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(
        IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    /// <summary>
    /// Finds a catalog containing this file's hash and returns the
    /// catalog path when the catalog itself verifies. Null means no
    /// catalog membership (or an unusable catalog stack).
    /// </summary>
    public static string? FindVerifyingCatalog(string path)
    {
        // BCRYPT_SHA256_ALGORITHM / BCRYPT_SHA1_ALGORITHM as pinned
        // wide strings for the acquire call.
        string? catalog = TryWithAlgorithm(path, "SHA256");
        catalog ??= TryWithAlgorithm(path, "SHA1");
        if (catalog is null)
        {
            return null;
        }

        // Membership alone is not trust: the catalog must verify.
        var (trusted, _) = WinTrust.VerifyFileTrust(catalog);
        return trusted ? catalog : null;
    }

    private static string? TryWithAlgorithm(string path, string algorithm)
    {
        IntPtr algPtr = Marshal.StringToHGlobalUni(algorithm);
        try
        {
            if (!CryptCATAdminAcquireContext2(out IntPtr admin, IntPtr.Zero, algPtr, IntPtr.Zero, 0)
                || admin == IntPtr.Zero)
            {
                return null;
            }

            try
            {
                using var file = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                uint needed = 0;
                if (!CryptCATAdminCalcHashFromFileHandle2(admin, file.SafeFileHandle.DangerousGetHandle(), ref needed, null, 0))
                {
                    return null;
                }

                var hash = new byte[needed];
                if (!CryptCATAdminCalcHashFromFileHandle2(admin, file.SafeFileHandle.DangerousGetHandle(), ref needed, hash, 0))
                {
                    return null;
                }

                IntPtr prev = IntPtr.Zero;
                try
                {
                    IntPtr info = CryptCATAdminEnumCatalogFromHash(admin, hash, needed, 0, prev);
                    if (info == IntPtr.Zero)
                    {
                        return null;
                    }

                    prev = info;
                    var catInfo = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                    if (!CryptCATCatalogInfoFromContext(info, ref catInfo, 0))
                    {
                        return null;
                    }

                    return string.IsNullOrWhiteSpace(catInfo.wszCatalogFile) ? null : catInfo.wszCatalogFile;
                }
                finally
                {
                    if (prev != IntPtr.Zero)
                    {
                        CryptCATAdminReleaseCatalogContext(admin, prev, 0);
                    }
                }
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or SEHException or IOException or UnauthorizedAccessException)
            {
                return null;
            }
            finally
            {
                CryptCATAdminReleaseContext(admin, 0);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(algPtr);
        }
    }
}
