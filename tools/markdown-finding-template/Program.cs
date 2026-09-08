// =============================================================================
// markdown-finding-template
//
// WHAT IT IS:  A generator that emits a clean, consistent Markdown write-up for a
//              finding from a few fields — or from a findings JSON file.
//
// WHAT IT'S FOR:  A good report is half the battle in bug bounty. This enforces a
//              standard structure (title, severity, target, stable signature,
//              description, evidence) so every submission looks the same and
//              nothing is forgotten. Generate a single finding on the command
//              line, or render a whole report from a JSON array produced by the
//              other tools.
//
// USAGE:       markdown-finding-template --title "IDOR on /orders/{id}" \
//                  --severity High --target https://api.target.com/orders/{id} \
//                  --desc "Any user can read another user's order by ID." \
//                  [--evidence "GET /orders/1042 -> 200 with foreign data"]
//
//              markdown-finding-template --json findings.json --report "Target X"
//
// SEVERITY:    Info | Low | Medium | High | Critical
// =============================================================================

using System.Text.Json;
using Toolkit.Core;

var cli = new Args(args);
if (cli.Has("help") || (cli.Get("title") is null && cli.Get("json") is null))
{
    Console.WriteLine("markdown-finding-template --title <t> --severity <s> --target <u> --desc <d> [--evidence <e>]");
    Console.WriteLine("markdown-finding-template --json <findings.json> [--report <title>]");
    return 0;
}

// Mode 1: render a whole report from a findings JSON array.
if (cli.Get("json") is { } jsonPath)
{
    if (!File.Exists(jsonPath)) { Console.Error.WriteLine($"error: file not found: {jsonPath}"); return 1; }
    var items = JsonSerializer.Deserialize<List<FindingDto>>(File.ReadAllText(jsonPath),
        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new();
    var findings = items.Select(i => i.ToFinding());
    Console.Write(MarkdownWriter.Report(findings, cli.Get("report", "Findings")));
    return 0;
}

// Mode 2: single finding from flags.
if (!Enum.TryParse<Severity>(cli.Get("severity", "Info"), true, out var sev)) sev = Severity.Info;
var f = new Finding(
    cli.Require("title"), sev,
    cli.Get("target", "(target)"),
    cli.Get("desc", "(description)"),
    cli.Get("evidence"));

Console.Write(MarkdownWriter.Finding(f));
return 0;

// DTO used only for JSON input.
public sealed class FindingDto
{
    public string Title { get; set; } = "";
    public string Severity { get; set; } = "Info";
    public string Target { get; set; } = "";
    public string Description { get; set; } = "";
    public string? Evidence { get; set; }

    public Finding ToFinding()
    {
        Enum.TryParse<Severity>(Severity, true, out var s);
        return new Finding(Title, s, Target, Description, Evidence);
    }
}
