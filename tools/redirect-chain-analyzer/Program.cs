// =============================================================================
// redirect-chain-analyzer
//
// WHAT IT IS:  A tool that follows a URL's redirect chain one hop at a time and
//              prints every step, flagging security-relevant transitions.
//
// WHAT IT'S FOR:  Redirects hide a lot: an HTTPS→HTTP downgrade that leaks a
//              token, a hop to a different host you didn't expect, or a chain
//              that eventually lands somewhere user-influenced. Browsers follow
//              all of this silently. This tool makes the chain explicit so you
//              can spot downgrades, cross-host jumps, and where a parameter you
//              control ends up. It's the reconnaissance half of open-redirect
//              and token-leak hunting.
//
// USAGE:       redirect-chain-analyzer --url https://target/go?next=... [--max 10] [--insecure]
//
// SCOPE:       Only follow chains for targets you are authorized to test.
// =============================================================================

using Toolkit.Core;

var cli = new Args(args);
if (cli.Has("help") || cli.Get("url") is null)
{
    Console.WriteLine("redirect-chain-analyzer --url <url> [--max 10] [--insecure]");
    return 0;
}

string url = cli.Require("url");
int max = cli.GetInt("max", 10);
using var http = new HttpEngine(allowRedirects: false, insecureTls: cli.Has("insecure"));

Console.WriteLine($"redirect-chain-analyzer  start: {url}\n");
string current = url;
string? prevHost = null; try { prevHost = new Uri(url).Host; } catch { }
bool prevHttps = url.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

for (int hop = 1; hop <= max; hop++)
{
    HttpResult r;
    try { r = await http.SendAsync("GET", current); }
    catch (Exception ex) { Console.Error.WriteLine($"hop {hop}: request failed: {ex.Message}"); return 1; }

    string loc = r.Header("Location") ?? "";
    Console.WriteLine($"hop {hop}: {r.Status} {r.Reason}  {current}");

    if (r.Status is < 300 or >= 400 || loc.Length == 0)
    {
        Console.WriteLine($"\nChain ended after {hop} hop(s) at status {r.Status}.");
        return 0;
    }

    // resolve relative Location
    Uri next; try { next = new Uri(new Uri(current), loc); } catch { Console.WriteLine($"  -> {loc} (unparseable)"); return 0; }
    Console.WriteLine($"     Location: {next}");

    if (prevHttps && next.Scheme == "http")
        Console.WriteLine("     [!] HTTPS -> HTTP downgrade (tokens in the request may leak in cleartext)");
    if (prevHost != null && !next.Host.Equals(prevHost, StringComparison.OrdinalIgnoreCase))
        Console.WriteLine($"     [!] cross-host redirect: {prevHost} -> {next.Host}");

    prevHost = next.Host;
    prevHttps = next.Scheme == "https";
    current = next.ToString();
}

Console.WriteLine($"\nStopped at --max {max} hops (possible redirect loop).");
return 0;
