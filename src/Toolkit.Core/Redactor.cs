using System.Text.RegularExpressions;

namespace Toolkit.Core;

/// <summary>
/// Redacts common secrets from text so evidence can be shared safely: JWTs,
/// bearer tokens, cookies, API keys, AWS keys, and email addresses. Pattern-
/// based and intentionally conservative — review output before publishing.
/// </summary>
public static class Redactor
{
    private static readonly (string Label, Regex Pattern)[] Rules =
    {
        ("JWT",     new Regex(@"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", RegexOptions.Compiled)),
        ("BEARER",  new Regex(@"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._\-]+", RegexOptions.Compiled)),
        ("COOKIE",  new Regex(@"(?i)(cookie:\s*)(.+)", RegexOptions.Compiled)),
        ("AWSKEY",  new Regex(@"AKIA[0-9A-Z]{16}", RegexOptions.Compiled)),
        ("APIKEY",  new Regex(@"(?i)(api[_-]?key\s*[=:]\s*)([A-Za-z0-9._\-]{12,})", RegexOptions.Compiled)),
        ("EMAIL",   new Regex(@"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", RegexOptions.Compiled)),
    };

    /// <summary>Returns the redacted text and the number of substitutions made.</summary>
    public static (string Text, int Count) Redact(string input)
    {
        int count = 0;
        string text = input;
        foreach (var (label, pattern) in Rules)
        {
            text = pattern.Replace(text, m =>
            {
                count++;
                // Preserve a captured prefix (e.g. "Authorization: Bearer ") when present.
                if (m.Groups.Count > 1 && m.Groups[1].Success)
                    return m.Groups[1].Value + $"[REDACTED:{label}]";
                return $"[REDACTED:{label}]";
            });
        }
        return (text, count);
    }
}
