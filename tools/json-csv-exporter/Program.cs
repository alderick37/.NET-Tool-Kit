// =============================================================================
// json-csv-exporter
//
// WHAT IT IS:  A converter that flattens a JSON array of objects into a CSV,
//              turning nested fields into dotted columns (a.b.c) and lining up a
//              consistent header row across all records.
//
// WHAT IT'S FOR:  Tooling and APIs spit out JSON; triage, sorting, and sharing
//              are easier in a spreadsheet. Export your findings, an endpoint
//              list, or any JSON result set to CSV so you can pivot it in
//              Excel/Sheets or hand it to a non-technical stakeholder. Nested
//              objects and arrays are flattened so nothing is lost.
//
// USAGE:       json-csv-exporter --in data.json --out data.csv
//              cat data.json | json-csv-exporter > data.csv
//
// INPUT:       A top-level JSON array, e.g. [ {..}, {..} ].
// =============================================================================

using Toolkit.Core;

var cli = new Args(args);
if (cli.Has("help"))
{
    Console.WriteLine("json-csv-exporter --in <data.json> --out <data.csv>");
    Console.WriteLine("Flattens a JSON array of objects into CSV.");
    return 0;
}

string json = cli.Get("in") is { } inPath
    ? (File.Exists(inPath) ? File.ReadAllText(inPath) : throw Fail($"file not found: {inPath}"))
    : Console.In.ReadToEnd();

List<Dictionary<string, string>> rows;
try { rows = JsonFlattener.FlattenArray(json); }
catch (Exception ex) { Console.Error.WriteLine($"error: {ex.Message}"); return 1; }

string csv = CsvWriter.Write(rows);

if (cli.Get("out") is { } outPath)
{
    File.WriteAllText(outPath, csv);
    Console.Error.WriteLine($"wrote {rows.Count} row(s) -> {outPath}");
}
else
{
    Console.Write(csv);
}
return 0;

static Exception Fail(string msg) => new InvalidOperationException(msg);
