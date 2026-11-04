using System.Text.RegularExpressions;

namespace Sentinel.Engine.Agent;

// Boundary redaction for anything leaving the PC (05 §7). Applied
// by the tools that emit text, never left to prompt wording.
// Conservative by design: it redacts `key=value`/`key: value`
// shapes for secret-like keys and strips the user profile prefix
// from paths. It is NOT a DLP guarantee — see limits in 10.
public static class SecretRedactor
{
    private static readonly Regex SecretLine = new(
        @"(?im)^(?<prefix>[^:\r\n]{0,80}?(password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|bearer|connectionstring)[^:\r\n=:]{0,40}?)\s*[:=]\s*(?<value>\S{1,256})",
        RegexOptions.Compiled);

    private const string Mask = "<redacted>";

    public static string RedactSecrets(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text;
        }

        return SecretLine.Replace(text, m => m.Groups["prefix"].Value + "= " + Mask);
    }

    // Class C rule: user-specific path prefixes become <user>.
    // Replaces EVERY occurrence (P1-04: prose embeds paths
    // mid-string), case-insensitively, tolerating / vs \.
    // Conservative: a longer name sharing the profile prefix
    // (…\Bob inside …\Bobby) is redacted too. Still NOT a DLP
    // guarantee — arbitrary prose may name the user other ways.
    public static string RedactUserPrefix(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text;
        }

        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrEmpty(profile))
        {
            return text;
        }

        // [\\/]+ (run, not single): serialized JSON doubles every
        // backslash, so the boundary check must match C:\\Users too.
        string pattern = Regex.Escape(profile)
            .Replace("/", "[\\\\/]+")
            .Replace("\\\\", "[\\\\/]+");
        return Regex.Replace(text, pattern, "<user>", RegexOptions.IgnoreCase);
    }
}
