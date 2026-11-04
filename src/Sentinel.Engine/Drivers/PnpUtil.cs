namespace Sentinel.Engine.Drivers;

// One third-party driver package from `pnputil /enum-drivers`.
// Version keeps the raw "date + version" form; DriverMatching
// normalizes it for compares.
public sealed record StorePackage(
    string PublishedName,
    string? OriginalName,
    string? Provider,
    string? ClassName,
    string? ClassGuid,
    string? Version,
    string? Signer,
    string? ExtensionId);

// D41: pure parser for `pnputil /enum-drivers` output. Blocks are
// separated by blank lines; fields are "Key:<spaces>value". Blocks
// without a Published Name are skipped (a rollback target without a
// store name is unusable — skipping beats guessing).
public static class PnpUtilParser
{
    public static IReadOnlyList<StorePackage> ParseEnumDrivers(string text)
    {
        var packages = new List<StorePackage>();
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        void Flush()
        {
            if (fields.TryGetValue("Published Name", out string? published) &&
                !string.IsNullOrWhiteSpace(published))
            {
                packages.Add(new StorePackage(
                    published.Trim(),
                    Get("Original Name"),
                    Get("Provider Name"),
                    Get("Class Name"),
                    Get("Class GUID"),
                    Get("Driver Version"),
                    Get("Signer Name"),
                    Get("Extension ID")));
            }

            fields.Clear();
        }

        string? Get(string key) =>
            fields.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value)
                ? value.Trim()
                : null;

        foreach (string raw in text.Split('\n'))
        {
            string line = raw.TrimEnd('\r').TrimEnd();
            if (line.Length == 0)
            {
                Flush();
                continue;
            }

            int colon = line.IndexOf(':');
            if (colon <= 0)
            {
                continue;
            }

            string key = line.Substring(0, colon).Trim();
            string value = line.Substring(colon + 1).Trim();
            if (key.Length > 0)
            {
                fields[key] = value;
            }
        }

        Flush();
        return packages;
    }
}
