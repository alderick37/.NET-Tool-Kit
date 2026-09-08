// =============================================================================
// cors-auditor
//
// WHAT IT IS:  A probe that sends a target URL several crafted Origin headers and
//              inspects the Access-Control-Allow-Origin / -Allow-Credentials
//              response headers for misconfigurations.
//
// WHAT IT'S FOR:  CORS bugs are easy to miss by hand because you have to try a
//              few different Origins and read the response headers carefully.
//              This automates the classic checks: does the server reflect an
//              arbitrary Origin? Does it trust "null"? Does it combine a
//              wildcard with credentials? Any of these can let a malicious site
//              read authenticated responses. Findings come out ranked so you
//              know which are worth writing up.
//
// USAGE:       cors-auditor --url https://api.target.com/me [--insecure]
//
// SCOPE:       Only test targets you are authorized to test.
// =============================================================================

using Toolkit.Core;

var cli = new Args(args);
if (cli.Has("help") || cli.Get("url") is null)
{
    Console.WriteLine("cors-auditor --url <url> [--insecure]");
    Console.WriteLine("Probes CORS handling with several Origin headers and flags misconfig.");
    return 0;
}

string url = cli.Require("url");
string host; try { host = new Uri(url).Host; } catch { Console.Error.WriteLine("error: invalid url"); return 1; }

string[] origins = { $"https://evil.example", "null", $"https://{host}.evil.example" };
using var http = new HttpEngine(insecureTls: cli.Has("insecure"), allowRedirects: false);

var all = new List<Finding>();
Console.WriteLine($"cors-auditor  {url}\n");
foreach (var origin in origins)
{
    try
    {
        var r = await http.SendAsync("GET", url, new Dictionary<string, string> { ["Origin"] = origin });
        string? acao = r.Header("Access-Control-Allow-Origin");
        string? acac = r.Header("Access-Control-Allow-Credentials");
        Console.WriteLine($"Origin: {origin,-30} -> ACAO: {acao ?? "(none)"}   ACAC: {acac ?? "(none)"}");
        all.AddRange(CorsAnalyzer.Analyze(origin, url, acao, acac));
    }
    catch (Exception ex) { Console.Error.WriteLine($"  request failed for Origin {origin}: {ex.Message}"); }
}

var unique = all.GroupBy(f => f.Signature()).Select(g => g.First()).ToList();
Console.WriteLine();
if (unique.Count == 0) { Console.WriteLine("No CORS misconfiguration flagged."); return 0; }

Console.WriteLine("== Findings ==");
foreach (var f in unique.OrderByDescending(f => f.Severity))
    Console.WriteLine($"[{f.Severity,-8}] {f.Title}\n            {f.Description}");
return 0;
