// =============================================================================
// redaction-tool
//
// WHAT IT IS:  A scrubber that removes secrets from text before you share it —
//              JWTs, bearer tokens, cookies, API keys, AWS keys, and emails are
//              replaced with [REDACTED:TYPE] markers.
//
// WHAT IT'S FOR:  Bug-bounty reports and evidence often contain live tokens or
//              PII that must not leave your machine intact. Run your request/
//              response logs (or a HAR) through this before pasting them into a
//              report or ticket. It preserves useful prefixes (like
//              "Authorization: Bearer ") so the evidence still reads correctly
//              while the secret itself is gone.
//
// USAGE:       redaction-tool --in evidence.txt --out evidence.redacted.txt
//              cat log.txt | redaction-tool          (reads stdin, writes stdout)
//
// NOTE:        Pattern-based and conservative — always eyeball the output.
// =============================================================================

using Toolkit.Core;

var cli = new Args(args);
if (cli.Has("help"))
{
    Console.WriteLine("redaction-tool --in <file> --out <file>   |   cat file | redaction-tool");
    return 0;
}

string input;
if (cli.Get("in") is { } inPath)
{
    if (!File.Exists(inPath)) { Console.Error.WriteLine($"error: file not found: {inPath}"); return 1; }
    input = File.ReadAllText(inPath);
}
else
{
    input = Console.In.ReadToEnd();
}

var (text, count) = Redactor.Redact(input);

if (cli.Get("out") is { } outPath)
{
    File.WriteAllText(outPath, text);
    Console.Error.WriteLine($"redacted {count} secret(s) -> {outPath}");
}
else
{
    Console.Write(text);
    Console.Error.WriteLine($"\n[redacted {count} secret(s)]");
}
return 0;
