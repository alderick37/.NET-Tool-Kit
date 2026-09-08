// Self-contained test suite for Toolkit.Core — no external framework, no network.
// Run:  dotnet run   (from tests/Toolkit.Tests)
using Toolkit.Core;

int failures = 0;
void Check(bool cond, string msg)
{
    Console.WriteLine((cond ? "  ok   " : "  FAIL ") + msg);
    if (!cond) failures++;
}

Console.WriteLine("== toolkit test suite ==");

// --- PathNormalizer ---
Console.WriteLine("PathNormalizer:");
Check(PathNormalizer.Normalize("/users/12/orders/98") == "/users/{id}/orders/{id}", "numeric ids -> {id}");
Check(PathNormalizer.Normalize("/a/550e8400-e29b-41d4-a716-446655440000") == "/a/{id}", "uuid -> {id}");
Check(PathNormalizer.Normalize("/static/logo.png") == "/static/logo.png", "leaves normal segments");

// --- HarParser ---
Console.WriteLine("HarParser:");
string har = """
{ "log": { "entries": [
  { "request": { "method": "GET", "url": "https://api.x.com/users/7?verbose=1",
      "queryString": [ { "name": "verbose", "value": "1" } ],
      "headers": [ { "name": "Authorization", "value": "Bearer z" } ] },
    "response": { "status": 200, "content": { "mimeType": "application/json" } } }
] } }
""";
var entries = HarParser.Parse(har);
Check(entries.Count == 1, "parses one entry");
Check(entries[0].Path == "/users/7" && entries[0].HasAuthHeader, "extracts path + auth flag");
Check(entries[0].QueryParams.Contains("verbose"), "extracts query params");

// --- Jwt ---
Console.WriteLine("Jwt:");
// {"alg":"none"} . {"sub":"1"} . (no sig)
string noneTok = B64("{\"alg\":\"none\",\"typ\":\"JWT\"}") + "." + B64("{\"sub\":\"1\"}") + ".";
var jf = Jwt.Analyze(noneTok);
Check(jf.Any(f => f.Title.Contains("alg=none")), "flags alg=none");
Check(jf.Any(f => f.Title.Contains("no signature")), "flags missing signature");
var parts = Jwt.Decode(noneTok);
Check(parts.HeaderJson.Contains("none") && !parts.HasSignature, "decodes header, detects no sig");

// --- Redactor ---
Console.WriteLine("Redactor:");
var (red, n) = Redactor.Redact("token=eyJhbGciOi.JhbGciOi.SIG email a@b.com");
Check(n >= 2 && red.Contains("[REDACTED:JWT]") && red.Contains("[REDACTED:EMAIL]"), "redacts jwt + email");
Check(!red.Contains("a@b.com"), "email actually removed");

// --- JsonFlattener + CsvWriter ---
Console.WriteLine("Json/Csv:");
var rows = JsonFlattener.FlattenArray("""[ {"a":1,"b":{"c":2}}, {"a":3,"d":"x,y"} ]""");
Check(rows[0]["b.c"] == "2", "flattens nested key");
string csv = CsvWriter.Write(rows);
Check(csv.Contains("a,b.c,d"), "csv header is union of keys");
Check(csv.Contains("\"x,y\""), "csv escapes commas");

// --- CorsAnalyzer ---
Console.WriteLine("CorsAnalyzer:");
var cf = CorsAnalyzer.Analyze("https://evil.example", "t", "https://evil.example", "true");
Check(cf.Any(f => f.Title.Contains("reflected") && f.Severity == Severity.High), "flags reflected origin + creds as High");
var cf2 = CorsAnalyzer.Analyze("null", "t", "null", null);
Check(cf2.Any(f => f.Title.Contains("null Origin")), "flags null origin");

// --- Finding signature / dedup ---
Console.WriteLine("Finding:");
var a = new Finding("X", Severity.High, "t", "d1");
var b = new Finding("x", Severity.High, "T", "d2-different-evidence");
Check(a.Signature() == b.Signature(), "signature ignores case & description");
var c = new Finding("Y", Severity.High, "t", "d");
Check(a.Signature() != c.Signature(), "different title -> different signature");

Console.WriteLine();
Console.WriteLine(failures == 0 ? $"ALL PASSED (0 failures)" : $"FAILURES PRESENT ({failures})");
Environment.Exit(failures == 0 ? 0 : 1);

static string B64(string s)
{
    var b = System.Text.Encoding.UTF8.GetBytes(s);
    return Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
