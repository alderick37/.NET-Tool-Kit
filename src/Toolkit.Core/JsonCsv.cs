using System.Text;
using System.Text.Json;

namespace Toolkit.Core;

/// <summary>Flattens JSON objects into dotted-key/value rows.</summary>
public static class JsonFlattener
{
    /// <summary>
    /// Given a JSON array of objects, returns one dictionary per object with
    /// nested keys flattened as "a.b.c". Arrays are indexed as "a.0", "a.1".
    /// </summary>
    public static List<Dictionary<string, string>> FlattenArray(string json)
    {
        var rows = new List<Dictionary<string, string>>();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Array)
            throw new FormatException("expected a top-level JSON array");

        foreach (var item in root.EnumerateArray())
        {
            var row = new Dictionary<string, string>();
            Flatten(item, "", row);
            rows.Add(row);
        }
        return rows;
    }

    private static void Flatten(JsonElement el, string prefix, Dictionary<string, string> row)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var p in el.EnumerateObject())
                    Flatten(p.Value, prefix.Length == 0 ? p.Name : $"{prefix}.{p.Name}", row);
                break;
            case JsonValueKind.Array:
                int i = 0;
                foreach (var item in el.EnumerateArray())
                    Flatten(item, $"{prefix}.{i++}", row);
                break;
            case JsonValueKind.Null:
                row[prefix] = "";
                break;
            default:
                row[prefix] = el.ToString();
                break;
        }
    }
}

/// <summary>Writes rows of data as RFC-4180 CSV.</summary>
public static class CsvWriter
{
    public static string Write(List<Dictionary<string, string>> rows)
    {
        // Column order = union of keys, first-seen order preserved.
        var columns = new List<string>();
        var seen = new HashSet<string>();
        foreach (var r in rows)
            foreach (var k in r.Keys)
                if (seen.Add(k)) columns.Add(k);

        var sb = new StringBuilder();
        sb.AppendLine(string.Join(",", columns.Select(Escape)));
        foreach (var r in rows)
            sb.AppendLine(string.Join(",", columns.Select(c => Escape(r.TryGetValue(c, out var v) ? v : ""))));
        return sb.ToString();
    }

    private static string Escape(string field)
    {
        if (field.Contains('"') || field.Contains(',') || field.Contains('\n') || field.Contains('\r'))
            return "\"" + field.Replace("\"", "\"\"") + "\"";
        return field;
    }
}
