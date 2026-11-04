using System.Text.Json;

namespace Sentinel.Store;

// T55: the saved-report library. Files, not database rows: one
// JSON document per saved draft, named by timestamp. The library
// is deliberately dumb — it stores and returns JSON text; the
// Reports page owns the draft shape (so old files that no longer
// parse stay readable as files, and the page reports the parse
// failure honestly instead of crashing the library list).
public sealed record SavedReportEntry(
    string FileName,
    string SavedLocal,
    long Bytes);

public sealed class ReportLibrary
{
    private readonly string _directory;

    public ReportLibrary(string directory)
    {
        _directory = directory;
        Directory.CreateDirectory(_directory);
    }

    public SavedReportEntry Save(string reportJson)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reportJson);
        string name = $"report-{DateTime.Now:yyyyMMdd-HHmmss-fff}.json";
        string path = Path.Combine(_directory, name);
        File.WriteAllText(path, reportJson);
        var info = new FileInfo(path);
        return new SavedReportEntry(
            name, info.LastWriteTime.ToString("d MMM yyyy HH:mm"), info.Length);
    }

    public IReadOnlyList<SavedReportEntry> List()
    {
        var entries = new List<SavedReportEntry>();
        string[] files;
        try
        {
            files = Directory.GetFiles(_directory, "report-*.json");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return entries;
        }

        Array.Sort(files, StringComparer.OrdinalIgnoreCase);
        Array.Reverse(files);
        foreach (string file in files.Take(100))
        {
            try
            {
                var info = new FileInfo(file);
                entries.Add(new SavedReportEntry(
                    info.Name, info.LastWriteTime.ToString("d MMM yyyy HH:mm"), info.Length));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // One unreadable file never breaks the list.
            }
        }

        return entries;
    }

    // Returns null for unknown names, path trickery, unreadable
    // files, and non-JSON content. Never throws.
    public string? Load(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName)
            || fileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0
            || !fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
            || !fileName.StartsWith("report-", StringComparison.OrdinalIgnoreCase)
            || fileName.Contains("..", StringComparison.Ordinal))
        {
            return null;
        }

        string path = Path.Combine(_directory, fileName);
        string full;
        try
        {
            full = Path.GetFullPath(path);
            if (!full.StartsWith(Path.GetFullPath(_directory), StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            string text = File.ReadAllText(full);
            using var _ = JsonDocument.Parse(text);
            return text;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }
}
