// =============================================================================
// finding-deduplicator
//
// WHAT IT IS:  A de-duplicator for a findings JSON array. It computes a stable
//              signature (title + target + severity) for each finding and drops
//              repeats, keeping the first occurrence.
//
// WHAT IT'S FOR:  When you merge output from several tools or several runs, the
//              same issue shows up many times — the same CORS misconfig on the
//              same endpoint, the same reflected parameter. Feeding everything
//              through this collapses duplicates so your report and your triage
//              queue only contain distinct issues. It reports how many it
//              removed so you can sanity-check the collapse.
//
// USAGE:       finding-deduplicator --in findings.json --out unique.json
//              cat findings.json | finding-deduplicator > unique.json
//
// INPUT:       JSON array of {title, severity, target, description, evidence?}.
// =============================================================================

using System.Text.Json;
using Toolkit.Core;

var cli = new Args(args);
if (cli.Has("help"))
{
    Console.WriteLine("finding-deduplicator --in <findings.json> --out <unique.json>");
    return 0;
}

string json = cli.Get("in") is { } inPath
    ? (File.Exists(inPath) ? File.ReadAllText(inPath) : Bail($"file not found: {inPath}"))
    : Console.In.ReadToEnd();

List<DedupDto> items;
try
{
    items = JsonSerializer.Deserialize<List<DedupDto>>(json,
        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new();
}
catch (Exception ex) { Console.Error.WriteLine($"error: {ex.Message}"); return 1; }

var seen = new HashSet<string>();
var unique = new List<DedupDto>();
foreach (var it in items)
    if (seen.Add(it.ToFinding().Signature()))
        unique.Add(it);

string outJson = JsonSerializer.Serialize(unique, new JsonSerializerOptions { WriteIndented = true });
if (cli.Get("out") is { } outPath) File.WriteAllText(outPath, outJson);
else Console.WriteLine(outJson);

Console.Error.WriteLine($"{items.Count} in -> {unique.Count} unique ({items.Count - unique.Count} duplicate(s) removed)");
return 0;

static string Bail(string msg) { Console.Error.WriteLine($"error: {msg}"); Environment.Exit(1); return ""; }

public sealed class DedupDto
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
