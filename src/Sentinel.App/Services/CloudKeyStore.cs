using System.Runtime.InteropServices;

namespace Sentinel.App.Services;

// Owner-held cloud key (09 A15 decision 8): a Windows Credential
// Manager generic credential. The app never logs or displays the
// key value; reads go only into the adapter's auth header.
// Writes happen ONLY through the explicit Settings Save/Remove
// buttons (SaveKey/DeleteKey); reads return null when absent
// (honest offline states, never a crash). Owner may also store
// it once by hand:
//
//   cmdkey /generic:Sentinel/MetaModelApi /user:apikey /pass:<KEY>
public sealed class CloudKeyStore
{
    public const string DefaultTarget = "Sentinel/MetaModelApi";

    private const int CredTypeGeneric = 1;

    private const int CredPersistEnterprise = 3;

    private readonly string _target;

    public CloudKeyStore(string target = DefaultTarget)
    {
        _target = target;
    }

    public string Target => _target;

    public bool HasKey() => ReadKey() is not null;

    // Writes (or overwrites) the vault entry. Throws Win32Exception
    // on failure so the UI can say so honestly. The value is pinned
    // only for the duration of the call.
    public void SaveKey(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            throw new ArgumentException("Key must not be empty.", nameof(key));
        }

        byte[] blob = System.Text.Encoding.Unicode.GetBytes(key);
        var handle = GCHandle.Alloc(blob, GCHandleType.Pinned);
        try
        {
            var cred = new NativeCredential
            {
                Flags = 0,
                Type = CredTypeGeneric,
                TargetName = _target,
                Comment = "Sentinel cloud model key",
                LastWritten = 0,
                CredentialBlobSize = blob.Length,
                CredentialBlob = handle.AddrOfPinnedObject(),
                Persist = CredPersistEnterprise,
                AttributeCount = 0,
                Attributes = nint.Zero,
                TargetAlias = null!,
                UserName = "apikey",
            };
            if (!CredWriteW(ref cred, 0))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            Array.Clear(blob, 0, blob.Length);
            handle.Free();
        }
    }

    // Removes the vault entry. Missing entry = success (idempotent).
    public void DeleteKey()
    {
        if (!CredDeleteW(_target, CredTypeGeneric, 0))
        {
            int error = Marshal.GetLastWin32Error();
            const int NotFound = 1168; // ERROR_NOT_FOUND
            if (error != NotFound)
            {
                throw new System.ComponentModel.Win32Exception(error);
            }
        }
    }

    public string? ReadKey()
    {
        if (!CredReadW(_target, CredTypeGeneric, 0, out nint cred)
            || cred == nint.Zero)
        {
            return null;
        }

        try
        {
            var parsed = Marshal.PtrToStructure<NativeCredential>(cred);
            if (parsed.CredentialBlobSize <= 0 || parsed.CredentialBlob == nint.Zero)
            {
                return null;
            }

            // Generic-credential blobs are bytes; Meta keys are text.
            // UTF-16 first (Credential Manager's native shape), UTF-8
            // fallback. Trailing NULs trimmed, never logged.
            int size = (int)Math.Min(parsed.CredentialBlobSize, 64 * 1024);
            var bytes = new byte[size];
            Marshal.Copy(parsed.CredentialBlob, bytes, 0, size);
            string key = size % 2 == 0
                ? System.Text.Encoding.Unicode.GetString(bytes).TrimEnd('\0')
                : System.Text.Encoding.UTF8.GetString(bytes).TrimEnd('\0');
            return string.IsNullOrWhiteSpace(key) ? null : key;
        }
        finally
        {
            CredFree(cred);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NativeCredential
    {
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public nint CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public nint Attributes;
        public string TargetAlias;
        public string UserName;
    }

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredReadW(
        string target, int type, int flags, out nint credential);

    [DllImport("Advapi32.dll")]
    private static extern void CredFree(nint credential);

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredWriteW(ref NativeCredential credential, int flags);

    [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredDeleteW(string target, int type, int flags);
}
