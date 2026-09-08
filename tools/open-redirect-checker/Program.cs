// =============================================================================
// open-redirect-checker
//
// WHAT IT IS:  A focused tester that takes a URL with a redirect parameter and
//              tries a set of payloads to see whether the server will bounce a
//              user to an attacker-controlled host.
//
// WHAT IT'S FOR:  Open redirects are a staple finding (and a building block for
//              OAuth token theft and phishing). Manually trying //evil.com,
//              https://evil.com, backslash tricks, and whitespace tricks is
//              tedious. Put FUZZ where the value goes and this fires the common
//              bypasses, follows the immediate response, and reports any payload
//              that lands off the original host.
//
// USAGE:       open-redirect-checker --url "https://site/login?next=FUZZ"
//              (the literal token FUZZ marks the injection point)
//
// SCOPE:       Only test targets you are authorized to test.
// =============================================================================

using Toolkit.Core;

var cli = new Args(args);
if (cli.Has("help") || cli.Get("url") is null)
{
    Console.WriteLine("open-redirect-checker --url \"https://site/login?next=FUZZ\" [--insecure]");
    Console.WriteLine("Put the literal token FUZZ where the redirect value belongs.");
    return 0;
}

string template = cli.Require("url");
if (!template.Contains("FUZZ"))
{
    Console.Error.WriteLine("error: the URL must contain the literal token FUZZ marking the injection point");
    return 1;
}

string origHost; try { origHost = new Uri(template.Replace("FUZZ", "x")).Host; }
catch { Console.Error.WriteLine("error: invalid url"); return 1; }

// A compact set of well-known open-redirect payloads.
string[] payloads =
{
    "https://evil.example",
    "//evil.example",
    "/\\evil.example",
    "https:/evil.example",
    "https://evil.example%2f%2f",
    "https://" + origHost + ".evil.example",
    "%09https://evil.example",
};

using var http = new HttpEngine(allowRedirects: false, insecureTls: cli.Has("insecure"));
Console.WriteLine($"open-redirect-checker  {template}\n(original host: {origHost})\n");

int hits = 0;
foreach (var p in payloads)
{
    string url = template.Replace("FUZZ", Uri.EscapeDataString(p));
    try
    {
        var r = await http.SendAsync("GET", url);
        string loc = r.Header("Location") ?? "";
        string verdict = "-";
        if (r.Status is >= 300 and < 400 && loc.Length > 0)
        {
            string? locHost = null;
            try { locHost = new Uri(new Uri(url), loc).Host; } catch { }
            if (locHost != null && !locHost.Equals(origHost, StringComparison.OrdinalIgnoreCase))
            { verdict = $"OPEN REDIRECT -> {locHost}"; hits++; }
        }
        Console.WriteLine($"[{r.Status}] {p,-40} {(verdict == "-" ? "" : "  " + verdict)}");
    }
    catch (Exception ex) { Console.WriteLine($"[err] {p,-40}  {ex.Message}"); }
}

Console.WriteLine($"\n{hits} payload(s) redirected off-host.");
return hits > 0 ? 0 : 0;
