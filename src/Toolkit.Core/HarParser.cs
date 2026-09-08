using System.Text.Json;
using System.Text.RegularExpressions;

namespace Toolkit.Core;

/// <summary>One request/response pair extracted from a HAR capture.</summary>
public sealed record HarEntry(
    string Method,
    string Url,
    string Path,
    IReadOnlyList<string> QueryParams,
    bool HasAuthHeader,
    int Status,
    string MimeType);

/// <summary>Parses browser/proxy HAR (HTTP Archive) files.</summary>
public static class HarParser
{
    public static List<HarEntry> Parse(string harJson)
    {
        var entries = new List<HarEntry>();
        using var doc = JsonDocument.Parse(harJson);
        if (!doc.RootElement.TryGetProperty("log", out var log) ||
            !log.TryGetProperty("entries", out var arr))
            return entries;

        foreach (var e in arr.EnumerateArray())
        {
            var req = e.GetProperty("request");
            string method = req.GetProperty("method").GetString() ?? "GET";
            string url = req.GetProperty("url").GetString() ?? "";
            string path = url;
            try { path = new Uri(url).AbsolutePath; } catch { /* leave as-is */ }

            var qp = new List<string>();
            if (req.TryGetProperty("queryString", out var qs))
                foreach (var q in qs.EnumerateArray())
                    if (q.TryGetProperty("name", out var n) && n.GetString() is { } name)
                        qp.Add(name);

            bool auth = false;
            if (req.TryGetProperty("headers", out var hs))
                foreach (var h in hs.EnumerateArray())
                    if (h.TryGetProperty("name", out var hn) &&
                        (hn.GetString()?.Equals("authorization", StringComparison.OrdinalIgnoreCase) == true ||
                         hn.GetString()?.Equals("cookie", StringComparison.OrdinalIgnoreCase) == true))
                        auth = true;

            int status = 0;
            string mime = "";
            if (e.TryGetProperty("response", out var rsp))
            {
                if (rsp.TryGetProperty("status", out var st)) status = st.GetInt32();
                if (rsp.TryGetProperty("content", out var c) &&
                    c.TryGetProperty("mimeType", out var mt)) mime = mt.GetString() ?? "";
            }

            entries.Add(new HarEntry(method, url, path, qp, auth, status, mime));
        }
        return entries;
    }
}

/// <summary>
/// Collapses volatile path segments (numeric IDs, UUIDs, hashes) into a
/// placeholder so that /users/12 and /users/98 group as /users/{id}.
/// </summary>
public static class PathNormalizer
{
    private static readonly Regex Numeric = new(@"^\d+$", RegexOptions.Compiled);
    private static readonly Regex Uuid = new(@"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", RegexOptions.Compiled);
    private static readonly Regex LongHex = new(@"^[0-9a-fA-F]{16,}$", RegexOptions.Compiled);

    public static string Normalize(string path)
    {
        var parts = path.Split('/');
        for (int i = 0; i < parts.Length; i++)
        {
            string p = parts[i];
            if (p.Length == 0) continue;
            if (Numeric.IsMatch(p) || Uuid.IsMatch(p) || LongHex.IsMatch(p))
                parts[i] = "{id}";
        }
        return string.Join('/', parts);
    }
}
