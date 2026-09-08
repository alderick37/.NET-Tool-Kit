// =============================================================================
// jwt-inspector
//
// WHAT IT IS:  A JSON Web Token decoder and safety linter. It does NOT verify or
//              crack signatures — it decodes the header and payload and flags the
//              weaknesses hunters look for.
//
// WHAT IT'S FOR:  Paste a JWT you captured (from a cookie, Authorization header,
//              or local storage) and instantly see its claims and the red flags:
//              alg=none, an unsigned token, a symmetric (HMAC) algorithm that
//              might use a guessable secret, a missing or already-passed exp,
//              an unusually long lifetime, or secrets accidentally stuffed into
//              claims. It turns "here's an opaque token" into "here's exactly
//              what to test next."
//
// USAGE:       jwt-inspector <token>
//              jwt-inspector --file token.txt
//
// SCOPE:       Only inspect tokens issued to you or on targets you may test.
// =============================================================================

using Toolkit.Core;

var cli = new Args(args);
string? token = cli.Get("file") is { } f && File.Exists(f)
    ? File.ReadAllText(f).Trim()
    : cli.Positional.FirstOrDefault();

if (string.IsNullOrWhiteSpace(token) || cli.Has("help"))
{
    Console.WriteLine("jwt-inspector <token>   |   jwt-inspector --file token.txt");
    Console.WriteLine("Decodes a JWT and flags common weaknesses (no verification).");
    return token is null ? 0 : 0;
}

try
{
    var parts = Jwt.Decode(token);
    Console.WriteLine("== Header ==");
    Console.WriteLine(Pretty(parts.HeaderJson));
    Console.WriteLine("\n== Payload ==");
    Console.WriteLine(Pretty(parts.PayloadJson));
    Console.WriteLine($"\n== Signature present: {parts.HasSignature} ==\n");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"error: {ex.Message}");
    return 1;
}

var findings = Jwt.Analyze(token);
if (findings.Count == 0)
{
    Console.WriteLine("No obvious weaknesses flagged.");
    return 0;
}

Console.WriteLine("== Findings ==");
foreach (var fnd in findings.OrderByDescending(x => x.Severity))
    Console.WriteLine($"[{fnd.Severity,-8}] {fnd.Title}\n            {fnd.Description}");
return 0;

static string Pretty(string json)
{
    try
    {
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        return System.Text.Json.JsonSerializer.Serialize(doc.RootElement,
            new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
    }
    catch { return json; }
}
