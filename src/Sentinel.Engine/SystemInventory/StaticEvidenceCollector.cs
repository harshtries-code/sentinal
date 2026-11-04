using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sentinel.Engine.SystemInventory;

// Local static evidence (M4): hash + Authenticode signer for an
// explicitly caller-bounded path list. Read-only file reads, all
// computed on-device, nothing uploaded (analyzer service is a
// separate milestone, 10 §5). Never executes or opens files with
// handlers — hash stream + certificate parse only.
public static class StaticEvidenceCollector
{
    private const string Scope = "Static file evidence (SHA-256 + Authenticode, local only)";
    private const int DefaultMaxFiles = 20;

    public static CollectionResult<StaticFileEvidenceRecord> CheckFiles(
        IEnumerable<string> paths, int maxFiles = DefaultMaxFiles)
    {
        var observed = DateTime.UtcNow;
        if (maxFiles < 1)
        {
            maxFiles = 1;
        }

        var records = new List<StaticFileEvidenceRecord>();
        bool truncated = false;
        foreach (string path in paths)
        {
            if (records.Count >= maxFiles)
            {
                truncated = true;
                break;
            }

            records.Add(CheckOne(path));
        }

        return new CollectionResult<StaticFileEvidenceRecord>(
            CollectionStatus.Success, records, Scope, observed,
            Array.Empty<CollectionGap>(), truncated);
    }

    private static StaticFileEvidenceRecord CheckOne(string path)
    {
        FileInfo info;
        try
        {
            info = new FileInfo(path);
            if (!info.Exists || (info.Attributes & FileAttributes.Directory) != 0)
            {
                return new StaticFileEvidenceRecord(path, false, null, null, false, null, null, "NotFound");
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or NotSupportedException)
        {
            return new StaticFileEvidenceRecord(path, false, null, null, false, null, null, ex.GetType().Name);
        }

        string? hash = null;
        string? hashDetail = null;
        try
        {
            using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            hash = Convert.ToHexString(SHA256.HashData(stream));
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            hashDetail = ex.GetType().Name;
        }

        // Trust = embedded verify OR catalog membership with a
        // verified catalog. WinVerifyTrust alone reports NOSIGNATURE
        // for catalog-signed system files; the CryptCATAdmin* path
        // below is the Get-AuthenticodeSignature equivalent.
        var (trusted, code) = WinTrust.VerifyFileTrust(path);
        string? catalog = trusted ? null : CatalogTrust.FindVerifyingCatalog(path);
        bool signed = trusted || catalog is not null;
        string? subject = null;
        string? issuer = null;
        string? signDetail = hashDetail;
        try
        {
            // Base-class Subject/Issuer only: no X509Certificate2
            // conversion (whose X509Certificate import is obsolete).
            // Catalog-signed files donate the catalog's signer.
            using var cert = X509Certificate.CreateFromSignedFile(catalog ?? path);
            subject = cert.Subject;
            issuer = cert.Issuer;
            if (catalog is not null)
            {
                signDetail = signDetail is null
                    ? "Catalog:" + Path.GetFileName(catalog)
                    : signDetail + "+Catalog:" + Path.GetFileName(catalog);
            }
        }
        catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException)
        {
            if (!signed)
            {
                signDetail = signDetail is null
                    ? $"0x{code:X8}"
                    : signDetail + $"+0x{code:X8}";
            }
            else if (catalog is not null)
            {
                signDetail = signDetail is null
                    ? "Catalog:" + Path.GetFileName(catalog)
                    : signDetail + "+Catalog:" + Path.GetFileName(catalog);
            }
        }

        return new StaticFileEvidenceRecord(
            path, true, info.Length, hash, signed,
            BlankToNull(subject), BlankToNull(issuer), signDetail);
    }

    private static string? BlankToNull(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
