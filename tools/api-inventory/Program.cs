// =============================================================================
// api-inventory
//
// WHAT IT IS:  A recon aid that turns a HAR capture (exported from your
//              browser's DevTools "Network" tab, or from a proxy) into a clean
//              inventory of the API surface you touched.
//
// WHAT IT'S FOR:  During a bug-bounty engagement you browse the target app and
//              save the traffic as a .har file. This tool groups every request
//              into distinct endpoints — normalizing volatile path segments so
//              /users/12 and /users/98 collapse into /users/{id} — and shows,
//              per endpoint, which HTTP methods and query parameters appeared
//              and whether it was called with auth (Authorization/Cookie).
//              The result is a map of the attack surface to work through
//              systematically instead of ad hoc.
//
// USAGE:       api-inventory --har capture.har [--json]
//
// SCOPE:       Only analyze traffic from targets you are authorized to test.
// =============================================================================

using System.Text.Json;
using Toolkit.Core;

var cli = new Args(args);
if (cli.Has("help") || cli.Get("har") is null)
{
    Console.WriteLine("api-inventory --har <capture.har> [--json]");
    Console.WriteLine("Builds an endpoint inventory from a HAR capture.");
    return 0;
}

string harPath = cli.Require("har");
if (!File.Exists(harPath)) { Console.Error.WriteLine($"error: file not found: {harPath}"); return 1; }

List<HarEntry> entries;
try { entries = HarParser.Parse(File.ReadAllText(harPath)); }
catch (Exception ex) { Console.Error.WriteLine($"error: could not parse HAR: {ex.Message}"); return 1; }

// endpoint key = METHOD host/normalized-path
var groups = new Dictionary<string, (SortedSet<string> methods, SortedSet<string> pars, bool auth, int count)>();
foreach (var e in entries)
{
    string host = ""; try { host = new Uri(e.Url).Host; } catch { }
    string key = $"{host}{PathNormalizer.Normalize(e.Path)}";
    if (!groups.TryGetValue(key, out var g))
        g = (new SortedSet<string>(), new SortedSet<string>(), false, 0);
    g.methods.Add(e.Method);
    foreach (var p in e.QueryParams) g.pars.Add(p);
    g.auth |= e.HasAuthHeader;
    g.count += 1;
    groups[key] = g;
}

if (cli.Has("json"))
{
    var obj = groups.OrderBy(k => k.Key).Select(k => new
    {
        endpoint = k.Key,
        methods = k.Value.methods,
        parameters = k.Value.pars,
        authenticated = k.Value.auth,
        hits = k.Value.count
    });
    Console.WriteLine(JsonSerializer.Serialize(obj, new JsonSerializerOptions { WriteIndented = true }));
    return 0;
}

Console.WriteLine($"api-inventory  {entries.Count} requests -> {groups.Count} endpoints\n");
Console.WriteLine($"{"AUTH",-5} {"METHODS",-18} {"ENDPOINT"}");
foreach (var (key, g) in groups.OrderByDescending(k => k.Value.auth).ThenBy(k => k.Key))
{
    string methods = string.Join(",", g.methods);
    Console.WriteLine($"{(g.auth ? "yes" : "-"),-5} {methods,-18} {key}");
    if (g.pars.Count > 0)
        Console.WriteLine($"{"",-5} {"",-18} params: {string.Join(", ", g.pars)}");
}
return 0;
