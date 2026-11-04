using System.Security.Cryptography;

namespace Sentinel.Engine.Actions;

// Filesystem seam behind vault moves. Production moves are
// same-volume renames (atomic, no bytes copied); tests inject faults
// (full disk, vanished paths, corrupt writes) through this seam.
public interface IVaultFileIO
{
    void CreateDirectory(string path);
    bool FileExists(string path);
    long GetSize(string path);
    void MoveFile(string source, string destination);
    string ComputeSha256(string path);
}

public sealed class DiskVaultFileIO : IVaultFileIO
{
    public void CreateDirectory(string path) => Directory.CreateDirectory(path);

    public bool FileExists(string path) => File.Exists(path);

    public long GetSize(string path) => new FileInfo(path).Length;

    // No overwrite: the destination name embeds the unique vault ref,
    // so a collision means a bug — surfacing it beats clobbering.
    public void MoveFile(string source, string destination) =>
        File.Move(source, destination, overwrite: false);

    public string ComputeSha256(string path)
    {
        using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        return Convert.ToHexString(SHA256.HashData(stream));
    }
}

// Vault layout (pure): one directory per source volume under the
// vault root, so every move is a same-volume rename — fast, atomic,
// and (honestly) freeing no capacity. Item file names embed the
// unique vault ref plus the original name for human review.
public static class VaultLayout
{
    // "C:\..." -> "C"; UNC "\\srv\share\..." -> "srv__share";
    // anything else -> sanitized fallback (never empty, never a path).
    public static string VolumeLabelFor(string absolutePath)
    {
        string root = Path.GetPathRoot(absolutePath) ?? string.Empty;
        string trimmed = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string label = trimmed
            .Replace(Path.DirectorySeparatorChar, '_')
            .Replace(Path.AltDirectorySeparatorChar, '_')
            .Replace(":", string.Empty);
        foreach (char bad in Path.GetInvalidFileNameChars())
        {
            label = label.Replace(bad, '_');
        }

        label = label.Trim('_', ' ', '.');
        return string.IsNullOrEmpty(label) ? "volume" : label;
    }

    public static string ItemFileName(string vaultRef, string originalName)
    {
        string safe = originalName;
        foreach (char bad in Path.GetInvalidFileNameChars())
        {
            safe = safe.Replace(bad, '_');
        }

        safe = safe.Trim(' ', '.');
        if (string.IsNullOrEmpty(safe))
        {
            safe = "item";
        }

        if (safe.Length > 120)
        {
            safe = safe.Substring(0, 120);
        }

        return vaultRef + "__" + safe;
    }

    public static string ItemDir(string vaultRoot, string volumeLabel) =>
        Path.Combine(vaultRoot, volumeLabel);

    // Restore-conflict name: "photo (restored 2).jpg" beside the
    // original. NEVER overwrites the existing destination — existing
    // user data at the path wins over the restored copy's name.
    public static string RestoreConflictPath(string desiredPath, Func<string, bool> exists, int maxAttempts = 1000)
    {
        if (!exists(desiredPath))
        {
            return desiredPath;
        }

        string? dir = Path.GetDirectoryName(desiredPath);
        string stem = Path.GetFileNameWithoutExtension(desiredPath);
        string ext = Path.GetExtension(desiredPath);
        for (int n = 1; n <= maxAttempts; n++)
        {
            string candidate = (string.IsNullOrEmpty(dir) ? string.Empty : dir + Path.DirectorySeparatorChar) +
                $"{stem} (restored {n}){ext}";
            if (!exists(candidate))
            {
                return candidate;
            }
        }

        throw new InvalidOperationException(
            "No free restore name beside '" + desiredPath + "' after " + maxAttempts + " attempts.");
    }
}
