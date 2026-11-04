using System.IO.Compression;
using System.Text.Json;

namespace Sentinel.Engine.SystemInventory;

// READ-ONLY browser extension metadata: manifest.json files
// (Chromium) and the Firefox extension registry + in-package
// manifests. METADATA ONLY — the collector opens manifest files
// and nothing else: no history, cookies, storage, or page data
// (pinned by test: every opened path ends in manifest.json or
// extensions.json). Bounded: 256KB per file, 200 rows.
public static class BrowserExtensionCollector
{
    public const int MaxManifestBytes = 256 * 1024;
    public const int MaxExtensions = 200;

    public sealed record ChromiumVendor(string Browser, string RelativeDir);

    public static readonly IReadOnlyList<ChromiumVendor> ChromiumVendors =
    [
        new("Chrome", @"Google\Chrome\User Data"),
        new("Edge", @"Microsoft\Edge\User Data"),
        new("Brave", @"BraveSoftware\Brave-Browser\User Data"),
    ];

    public static CollectionResult<BrowserExtensionRecord> Collect(
        string? localAppData = null, string? roamingAppData = null)
    {
        const string scope = "Browser extensions (manifest metadata)";
        var observed = DateTime.UtcNow;
        var records = new List<BrowserExtensionRecord>();
        var gaps = new List<CollectionGap>();
        bool truncated = false;

        string local = localAppData ?? Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData);
        string roaming = roamingAppData ?? Environment.GetFolderPath(
            Environment.SpecialFolder.ApplicationData);

        foreach (var vendor in ChromiumVendors)
        {
            if (records.Count >= MaxExtensions)
            {
                truncated = true;
                break;
            }

            CollectChromium(vendor, Path.Combine(local, vendor.RelativeDir), records, gaps);
        }

        if (records.Count < MaxExtensions)
        {
            CollectFirefox(Path.Combine(roaming, @"Mozilla\Firefox\Profiles"), records, gaps);
        }
        else
        {
            truncated = true;
        }

        if (records.Count > MaxExtensions)
        {
            records.RemoveRange(MaxExtensions, records.Count - MaxExtensions);
            truncated = true;
        }

        if (truncated)
        {
            gaps.Add(new CollectionGap(scope, "Truncated", $"kept first {MaxExtensions}"));
        }

        var status = gaps.Count == 0 ? CollectionStatus.Success : CollectionStatus.Partial;
        return new CollectionResult<BrowserExtensionRecord>(
            status, records, scope, observed, gaps, truncated);
    }

    private static void CollectChromium(
        ChromiumVendor vendor, string userDataDir,
        List<BrowserExtensionRecord> records, List<CollectionGap> gaps)
    {
        string[] profiles;
        try
        {
            if (!Directory.Exists(userDataDir))
            {
                return;
            }

            profiles = Directory.GetDirectories(userDataDir);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            gaps.Add(new CollectionGap(vendor.Browser, "ProfilesUnreadable", ex.GetType().Name));
            return;
        }

        foreach (string profile in profiles)
        {
            string extRoot = Path.Combine(profile, "Extensions");
            string[] ids;
            try
            {
                if (!Directory.Exists(extRoot))
                {
                    continue;
                }

                ids = Directory.GetDirectories(extRoot);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                GapOnce(gaps, vendor.Browser, "ExtensionsUnreadable", ex.GetType().Name);
                continue;
            }

            foreach (string idDir in ids)
            {
                if (records.Count >= MaxExtensions)
                {
                    return;
                }

                string? manifest = NewestManifest(idDir);
                if (manifest is null)
                {
                    continue;
                }

                var record = ReadChromiumManifest(
                    vendor.Browser, Path.GetFileName(profile) ?? "profile",
                    Path.GetFileName(idDir) ?? "unknown", manifest);
                if (record is not null)
                {
                    records.Add(record);
                }
            }
        }
    }

    // Highest version dir wins (directory names sort; a tie keeps
    // first — versions are cosmetic here, not security claims).
    private static string? NewestManifest(string idDir)
    {
        try
        {
            var best = Directory.GetDirectories(idDir)
                .Select(v => Path.Combine(v, "manifest.json"))
                .Where(File.Exists)
                .OrderByDescending(p => p, StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault();
            return best;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static BrowserExtensionRecord? ReadChromiumManifest(
        string browser, string profile, string id, string manifestPath)
    {
        string json;
        try
        {
            var info = new FileInfo(manifestPath);
            if (!info.Exists || info.Length > MaxManifestBytes)
            {
                return null;
            }

            json = File.ReadAllText(manifestPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        return ParseManifest(browser, profile, id, json, manifestPath);
    }

    // Pure manifest read: name/version/permissions + whether
    // content scripts exist (presence only — script BODIES are
    // profile-adjacent content and are never opened).
    internal static BrowserExtensionRecord? ParseManifest(
        string browser, string profile, string id, string json, string manifestPath)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(json);
        }
        catch
        {
            return null;
        }

        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            string name = root.TryGetProperty("name", out var nameEl) &&
                nameEl.ValueKind == JsonValueKind.String &&
                !string.IsNullOrWhiteSpace(nameEl.GetString()) &&
                !nameEl.GetString()!.StartsWith("__MSG_", StringComparison.Ordinal)
                    ? nameEl.GetString()!
                    : id;
            string version = root.TryGetProperty("version", out var verEl) &&
                verEl.ValueKind == JsonValueKind.String
                    ? verEl.GetString() ?? "?"
                    : "?";
            var permissions = new List<string>();
            if (root.TryGetProperty("permissions", out var permsEl) &&
                permsEl.ValueKind == JsonValueKind.Array)
            {
                foreach (var perm in permsEl.EnumerateArray())
                {
                    if (perm.ValueKind == JsonValueKind.String &&
                        !string.IsNullOrWhiteSpace(perm.GetString()))
                    {
                        permissions.Add(perm.GetString()!);
                    }

                    if (permissions.Count >= 20)
                    {
                        break;
                    }
                }
            }

            // Manifest v3 splits API access across several keys.
            if (root.TryGetProperty("host_permissions", out var hostsEl) &&
                hostsEl.ValueKind == JsonValueKind.Array)
            {
                foreach (var host in hostsEl.EnumerateArray())
                {
                    if (host.ValueKind == JsonValueKind.String &&
                        !string.IsNullOrWhiteSpace(host.GetString()))
                    {
                        permissions.Add("host:" + host.GetString()!);
                    }

                    if (permissions.Count >= 20)
                    {
                        break;
                    }
                }
            }

            bool contentScripts = root.TryGetProperty("content_scripts", out var csEl) &&
                csEl.ValueKind == JsonValueKind.Array &&
                csEl.GetArrayLength() > 0;

            return new BrowserExtensionRecord(browser, profile, id, name, version,
                permissions, contentScripts, manifestPath);
        }
    }

    private static void CollectFirefox(
        string profilesDir,
        List<BrowserExtensionRecord> records, List<CollectionGap> gaps)
    {
        string[] profiles;
        try
        {
            if (!Directory.Exists(profilesDir))
            {
                return;
            }

            profiles = Directory.GetDirectories(profilesDir);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            gaps.Add(new CollectionGap("Firefox", "ProfilesUnreadable", ex.GetType().Name));
            return;
        }

        foreach (string profile in profiles)
        {
            string registry = Path.Combine(profile, "extensions.json");
            JsonDocument doc;
            try
            {
                var info = new FileInfo(registry);
                if (!info.Exists || info.Length > MaxManifestBytes * 4)
                {
                    continue;
                }

                doc = JsonDocument.Parse(File.ReadAllText(registry));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
            {
                GapOnce(gaps, "Firefox", "RegistryUnreadable", ex.GetType().Name);
                continue;
            }

            using (doc)
            {
                if (!doc.RootElement.TryGetProperty("addons", out var addons) ||
                    addons.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                foreach (var addon in addons.EnumerateArray())
                {
                    if (records.Count >= MaxExtensions)
                    {
                        return;
                    }

                    var record = ParseFirefoxAddon(
                        Path.GetFileName(profile) ?? "profile", profile, addon);
                    if (record is not null)
                    {
                        records.Add(record);
                    }
                }
            }
        }
    }

    internal static BrowserExtensionRecord? ParseFirefoxAddon(
        string profile, string profileDir, JsonElement addon)
    {
        if (addon.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        string? id = addon.TryGetProperty("id", out var idEl) &&
            idEl.ValueKind == JsonValueKind.String ? idEl.GetString() : null;
        string? version = addon.TryGetProperty("version", out var verEl) &&
            verEl.ValueKind == JsonValueKind.String ? verEl.GetString() : null;
        string? path = addon.TryGetProperty("path", out var pathEl) &&
            pathEl.ValueKind == JsonValueKind.String ? pathEl.GetString() : null;
        if (string.IsNullOrWhiteSpace(id))
        {
            return null;
        }

        // The signed package's own manifest is the permission
        // source; manifest.json ONLY (never package content).
        string manifestPath = path ?? "(registry only)";
        if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
        {
            try
            {
                using var zip = ZipFile.OpenRead(path!);
                var entry = zip.GetEntry("manifest.json");
                if (entry is not null && entry.Length <= MaxManifestBytes)
                {
                    using var reader = new StreamReader(entry.Open());
                    string json = reader.ReadToEnd();
                    var parsed = ParseManifest("Firefox", profile, id!, json, path!);
                    if (parsed is not null)
                    {
                        return parsed with { Version = version ?? parsed.Version };
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
            {
            }
        }

        // Registry-only row: honest about what wasn't inspected.
        return new BrowserExtensionRecord("Firefox", profile, id!, id!, version ?? "?",
            [], false, manifestPath);
    }

    private static void GapOnce(
        List<CollectionGap> gaps, string source, string reason, string? detail)
    {
        if (!gaps.Any(g => g.Source == source && g.Reason == reason))
        {
            gaps.Add(new CollectionGap(source, reason, detail));
        }
    }
}
