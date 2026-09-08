using System.Security.Cryptography;
using System.Text;

namespace Toolkit.Core;

public enum Severity { Info, Low, Medium, High, Critical }

/// <summary>A single observation or issue produced by a tool.</summary>
public sealed record Finding(
    string Title,
    Severity Severity,
    string Target,
    string Description,
    string? Evidence = null)
{
    /// <summary>
    /// A stable signature used for de-duplication: same title + target +
    /// severity collapse to the same hash regardless of wording of evidence.
    /// </summary>
    public string Signature()
    {
        string basis = $"{Title.Trim().ToLowerInvariant()}|{Target.Trim().ToLowerInvariant()}|{Severity}";
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(basis));
        return Convert.ToHexString(hash)[..16].ToLowerInvariant();
    }
}

/// <summary>Renders findings as consistent, report-ready Markdown.</summary>
public static class MarkdownWriter
{
    public static string Finding(Finding f)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"## {f.Title}");
        sb.AppendLine();
        sb.AppendLine($"- **Severity:** {f.Severity}");
        sb.AppendLine($"- **Target:** {f.Target}");
        sb.AppendLine($"- **Signature:** `{f.Signature()}`");
        sb.AppendLine();
        sb.AppendLine("### Description");
        sb.AppendLine(f.Description);
        if (!string.IsNullOrWhiteSpace(f.Evidence))
        {
            sb.AppendLine();
            sb.AppendLine("### Evidence");
            sb.AppendLine("```");
            sb.AppendLine(f.Evidence);
            sb.AppendLine("```");
        }
        return sb.ToString();
    }

    public static string Report(IEnumerable<Finding> findings, string title)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# {title}");
        sb.AppendLine();
        sb.AppendLine($"_Generated {DateTimeOffset.UtcNow:u}_");
        sb.AppendLine();
        foreach (var f in findings)
        {
            sb.AppendLine(Finding(f));
            sb.AppendLine("---");
            sb.AppendLine();
        }
        return sb.ToString();
    }
}
