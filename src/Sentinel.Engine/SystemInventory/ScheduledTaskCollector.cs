using System.Diagnostics;
using System.Text;
using System.Xml.Linq;

namespace Sentinel.Engine.SystemInventory;

// READ-ONLY scheduled-task inventory via schtasks.exe (no COM,
// no task creation/modification surface). List view is bounded
// (500 tasks); per-task XML detail is on-demand (one task at a
// time, from the UI drawer). Commands are SHOWN for inspection;
// Sentinel never runs them.
public static class ScheduledTaskCollector
{
    public const int MaxTasks = 500;

    public static CollectionResult<ScheduledTaskRecord> Collect(
        Func<string>? outputReader = null)
    {
        const string scope = "Scheduled tasks (schtasks list)";
        var observed = DateTime.UtcNow;
        if (Environment.OSVersion.Platform != PlatformID.Win32NT && outputReader is null)
        {
            return CollectionResult<ScheduledTaskRecord>.Fail(scope, "WindowsOnly");
        }

        string output;
        try
        {
            output = outputReader is not null
                ? outputReader()
                : Run("schtasks.exe", "/query /fo CSV /nh", TimeSpan.FromMinutes(2));
        }
        catch (Exception ex)
        {
            return CollectionResult<ScheduledTaskRecord>.Fail(
                scope, ex.GetType().Name, Trim(ex.Message));
        }

        var (records, unparsed) = ParseCsv(output, MaxTasks);
        var gaps = new List<CollectionGap>();
        if (unparsed > 0)
        {
            gaps.Add(new CollectionGap(scope, "UnparsedLines", unparsed.ToString()));
        }

        bool truncated = records.Count >= MaxTasks;
        if (truncated)
        {
            gaps.Add(new CollectionGap(scope, "Truncated", $"kept first {MaxTasks}"));
        }

        var status = gaps.Count == 0 ? CollectionStatus.Success : CollectionStatus.Partial;
        return new CollectionResult<ScheduledTaskRecord>(
            status, records, scope, observed, gaps, truncated);
    }

    // One task's triggers/actions/visibility. The caller names an
    // EXACT task path (from the list above); schtasks resolves it.
    public static ScheduledTaskDetail? ReadDetail(
        string taskName, Func<string>? xmlReader = null)
    {
        if (string.IsNullOrWhiteSpace(taskName))
        {
            return null;
        }

        string xml;
        try
        {
            xml = xmlReader is not null
                ? xmlReader()
                : Run("schtasks.exe", $"/query /tn \"{taskName.Trim()}\" /xml ONE",
                    TimeSpan.FromMinutes(1));
        }
        catch
        {
            return null;
        }

        return ParseXml(xml, taskName.Trim());
    }

    // schtasks CSV: "TaskName","Next Run Time","Status" (order
    // stable, fields quoted, inner quotes doubled).
    internal static (IReadOnlyList<ScheduledTaskRecord> Records, int Unparsed) ParseCsv(
        string output, int limit)
    {
        var records = new List<ScheduledTaskRecord>();
        int unparsed = 0;
        foreach (var line in output.Split('\n'))
        {
            if (records.Count >= limit)
            {
                break;
            }

            string trimmed = line.Trim();
            if (trimmed.Length == 0)
            {
                continue;
            }

            var fields = SplitCsv(trimmed);
            if (fields.Count < 3)
            {
                unparsed++;
                continue;
            }

            records.Add(new ScheduledTaskRecord(
                Unquote(fields[0]),
                EmptyToNull(Unquote(fields[1])),
                EmptyToNull(Unquote(fields[2])),
                fields.Count > 3 ? EmptyToNull(Unquote(fields[3])) : null));
        }

        return (records, unparsed);
    }

    internal static List<string> SplitCsv(string line)
    {
        var fields = new List<string>();
        var current = new StringBuilder();
        bool inQuotes = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (c == '"')
            {
                if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
                {
                    current.Append('"');
                    i++;
                }
                else
                {
                    inQuotes = !inQuotes;
                }
            }
            else if (c == ',' && !inQuotes)
            {
                fields.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(c);
            }
        }

        fields.Add(current.ToString());
        return fields;
    }

    private static string Unquote(string field)
    {
        field = field.Trim();
        if (field.Length >= 2 && field.StartsWith('"') && field.EndsWith('"'))
        {
            field = field.Substring(1, field.Length - 2).Replace("\"\"", "\"", StringComparison.Ordinal);
        }

        return field.Trim();
    }

    private static string? EmptyToNull(string value) =>
        string.IsNullOrWhiteSpace(value) || value == "N/A" ? null : value;

    // Task Scheduler XML (mit/task namespace). Unknown elements are
    // ignored — triggers summarize by element name + start bound.
    internal static ScheduledTaskDetail? ParseXml(string xml, string taskName)
    {
        if (string.IsNullOrWhiteSpace(xml))
        {
            return null;
        }

        XDocument doc;
        try
        {
            doc = XDocument.Parse(xml.Trim().TrimStart('\uFEFF'));
        }
        catch
        {
            return null;
        }

        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        var root = doc.Root;
        if (root is null)
        {
            return null;
        }

        var actions = new List<string>();
        foreach (var exec in root.Descendants(ns + "Exec"))
        {
            string command = (exec.Element(ns + "Command")?.Value ?? string.Empty).Trim();
            string args = (exec.Element(ns + "Arguments")?.Value ?? string.Empty).Trim();
            if (command.Length == 0)
            {
                continue;
            }

            actions.Add(args.Length == 0 ? command : command + " " + args);
        }

        foreach (var com in root.Descendants(ns + "ComHandler"))
        {
            string clsid = (com.Element(ns + "ClassId")?.Value ?? string.Empty).Trim();
            if (clsid.Length > 0)
            {
                actions.Add("COM handler " + clsid);
            }
        }

        var triggers = new List<string>();
        var triggersEl = root.Element(ns + "Triggers");
        if (triggersEl is not null)
        {
            foreach (var trigger in triggersEl.Elements())
            {
                string name = trigger.Name.LocalName;
                string start = (trigger.Element(ns + "StartBoundary")?.Value ?? string.Empty).Trim();
                string enabled = (trigger.Element(ns + "Enabled")?.Value ?? string.Empty).Trim();
                string summary = name;
                if (start.Length > 0)
                {
                    summary += " @ " + start;
                }

                if (enabled.Equals("false", StringComparison.OrdinalIgnoreCase))
                {
                    summary += " (disabled)";
                }

                triggers.Add(summary);
            }
        }

        string? author = root.Element(ns + "RegistrationInfo")?.Element(ns + "Author")?.Value?.Trim();
        bool hidden = root.Element(ns + "Settings")?.Element(ns + "Hidden")?.Value?
            .Trim().Equals("true", StringComparison.OrdinalIgnoreCase) == true;

        return new ScheduledTaskDetail(taskName, actions, triggers,
            string.IsNullOrWhiteSpace(author) ? null : author, hidden);
    }

    private static string Run(string exe, string args, TimeSpan timeout)
    {
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = exe,
            Arguments = args,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            // Default console decoding: schtasks writes OEM text,
            // not Unicode — forcing an encoding garbles it.
        }) ?? throw new InvalidOperationException("schtasks did not start.");
        var stdout = new StringBuilder();
        proc.OutputDataReceived += (_, e) => { if (e.Data is not null) { stdout.AppendLine(e.Data); } };
        proc.BeginOutputReadLine();
        string stderr = proc.StandardError.ReadToEnd();
        if (!proc.WaitForExit(timeout))
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException("schtasks timed out.");
        }

        if (proc.ExitCode != 0)
        {
            throw new InvalidOperationException($"schtasks exit {proc.ExitCode}: {Trim(stderr)}");
        }

        return stdout.ToString();
    }

    private static string Trim(string s)
    {
        s = (s ?? string.Empty).Trim().ReplaceLineEndings(" ");
        return s.Length <= 300 ? s : s[..300];
    }
}
