using System.Text.RegularExpressions;

namespace Sentinel.Engine.Drivers;

// Best-effort parse of Dell Command Update CLI scan output. DCU's
// text format is NOT a stable contract, so this parser claims little:
// title-like lines (letters + a version-ish token) become titles,
// everything else is counted, and the raw text is always preserved
// as the real evidence. The executor confirms the raw summary, never
// a parsed count alone.
public sealed record DcuScanParse(
    IReadOnlyList<string> Titles,
    int OtherLines,
    string RawSummary);

public static partial class DcuParser
{
    public static DcuScanParse Parse(string? output)
    {
        if (string.IsNullOrWhiteSpace(output))
        {
            return new DcuScanParse([], 0, "Catalogue scan produced no output.");
        }

        var titles = new List<string>();
        int other = 0;
        foreach (var raw in output.Split('\n'))
        {
            string line = raw.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            if (IsTitleLike(line))
            {
                titles.Add(TrimTitle(line));
            }
            else
            {
                other++;
            }
        }

        string summary = titles.Count == 0
            ? $"Catalogue scan complete: {other} output line(s), none recognizably an update title. " +
              "Raw log retained as evidence."
            : $"Catalogue scan complete: {titles.Count} update(s), {other} other line(s).";
        return new DcuScanParse(titles, other, summary);
    }

    // Letters AND a dotted-number token, not a bare path or flag line.
    private static bool IsTitleLike(string line)
    {
        if (line.StartsWith('-') || line.StartsWith('/') || line.StartsWith("C:\\", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return line.Any(char.IsLetter) && VersionToken().IsMatch(line);
    }

    private static string TrimTitle(string line)
    {
        line = line.TrimStart('-', '*', '>', ' ');
        return line.Length <= 200 ? line : line[..200];
    }

    [GeneratedRegex(@"\d+\.\d+")]
    private static partial Regex VersionToken();
}
