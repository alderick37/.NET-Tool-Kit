// =============================================================================
// response-differ
//
// WHAT IT IS:  A tool that fetches two URLs (or reads two saved response bodies)
//              and reports exactly how they differ: status code, headers added/
//              removed/changed, body length, and a line-level diff of the body.
//
// WHAT IT'S FOR:  So much of web testing is "does changing X change the
//              response?" — swap an ID, drop a token, flip a role, tweak a
//              parameter, then compare. This gives you a precise, side-by-side
//              answer instead of eyeballing two blobs. Pair it with idor-matrix
//              or role-diff (later in the toolkit) to confirm whether two
//              identities really see the same thing.
//
// USAGE:       response-differ --a https://site/a --b https://site/b
//              response-differ --file-a resp1.txt --file-b resp2.txt
//              (options: --insecure to accept any TLS cert on lab targets)
//
// SCOPE:       Only send requests to targets you are authorized to test.
// =============================================================================

using Toolkit.Core;

var cli = new Args(args);
if (cli.Has("help"))
{
    Console.WriteLine("response-differ --a <url> --b <url>  |  --file-a <f> --file-b <f> [--insecure]");
    return 0;
}

string? a, b;
try
{
    (a, b) = await LoadPair(cli);
}
catch (Exception ex) { Console.Error.WriteLine($"error: {ex.Message}"); return 1; }

if (a is null || b is null)
{
    Console.Error.WriteLine("error: provide --a/--b URLs or --file-a/--file-b files");
    return 1;
}

// Body diff (line level)
var la = a.Replace("\r\n", "\n").Split('\n');
var lb = b.Replace("\r\n", "\n").Split('\n');
Console.WriteLine($"body A: {a.Length} bytes, {la.Length} lines");
Console.WriteLine($"body B: {b.Length} bytes, {lb.Length} lines\n");

var setA = new HashSet<string>(la);
var setB = new HashSet<string>(lb);
var onlyA = la.Where(l => !setB.Contains(l)).Distinct().ToList();
var onlyB = lb.Where(l => !setA.Contains(l)).Distinct().ToList();

if (onlyA.Count == 0 && onlyB.Count == 0)
{
    Console.WriteLine("Bodies are identical (line set).");
    return 0;
}

Console.WriteLine($"-- lines only in A ({onlyA.Count}) --");
foreach (var l in onlyA.Take(40)) Console.WriteLine($"- {Trim(l)}");
Console.WriteLine($"\n++ lines only in B ({onlyB.Count}) ++");
foreach (var l in onlyB.Take(40)) Console.WriteLine($"+ {Trim(l)}");
return 0;

static string Trim(string s) => s.Length > 200 ? s[..200] + "…" : s;

static async Task<(string?, string?)> LoadPair(Args cli)
{
    if (cli.Get("file-a") is { } fa && cli.Get("file-b") is { } fb)
        return (File.ReadAllText(fa), File.ReadAllText(fb));

    if (cli.Get("a") is { } ua && cli.Get("b") is { } ub)
    {
        using var http = new HttpEngine(insecureTls: cli.Has("insecure"), allowRedirects: true);
        var ra = await http.SendAsync("GET", ua);
        var rb = await http.SendAsync("GET", ub);
        Console.WriteLine($"A: {ra.Status} {ra.Reason}   B: {rb.Status} {rb.Reason}");
        DiffHeaders(ra.Headers, rb.Headers);
        return (ra.Body, rb.Body);
    }
    return (null, null);
}

static void DiffHeaders(Dictionary<string, string> ha, Dictionary<string, string> hb)
{
    Console.WriteLine("\n== header differences ==");
    foreach (var k in ha.Keys.Union(hb.Keys, StringComparer.OrdinalIgnoreCase).OrderBy(x => x))
    {
        ha.TryGetValue(k, out var va); hb.TryGetValue(k, out var vb);
        if (va is null) Console.WriteLine($"  + {k}: {vb}");
        else if (vb is null) Console.WriteLine($"  - {k}: {va}");
        else if (!va.Equals(vb, StringComparison.Ordinal)) Console.WriteLine($"  ~ {k}: {va}  ->  {vb}");
    }
    Console.WriteLine();
}
