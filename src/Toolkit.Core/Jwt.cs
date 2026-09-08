using System.Text;
using System.Text.Json;

namespace Toolkit.Core;

public sealed record JwtParts(string HeaderJson, string PayloadJson, bool HasSignature);

/// <summary>
/// Decodes JWTs (no verification) and flags the classic weaknesses hunters look
/// for: alg=none, unsigned tokens, missing/expired exp, over-long lifetimes,
/// and secrets accidentally embedded in claims.
/// </summary>
public static class Jwt
{
    public static JwtParts Decode(string token)
    {
        var segs = token.Trim().Split('.');
        if (segs.Length < 2)
            throw new FormatException("not a JWT: expected at least header.payload");
        string header = Encoding.UTF8.GetString(Base64Url(segs[0]));
        string payload = Encoding.UTF8.GetString(Base64Url(segs[1]));
        bool sig = segs.Length >= 3 && segs[2].Length > 0;
        return new JwtParts(header, payload, sig);
    }

    public static List<Finding> Analyze(string token)
    {
        var findings = new List<Finding>();
        JwtParts parts;
        try { parts = Decode(token); }
        catch (Exception ex)
        {
            findings.Add(new Finding("JWT parse error", Severity.Info, "token", ex.Message));
            return findings;
        }

        using var hdoc = JsonDocument.Parse(parts.HeaderJson);
        string alg = hdoc.RootElement.TryGetProperty("alg", out var a) ? a.GetString() ?? "" : "";

        if (alg.Equals("none", StringComparison.OrdinalIgnoreCase))
            findings.Add(new Finding("alg=none accepted by token", Severity.High, "header",
                "Header declares 'none' — if the server honors it, the signature is not checked."));
        if (!parts.HasSignature)
            findings.Add(new Finding("Token has no signature segment", Severity.Medium, "token",
                "Third segment is empty; verify the server rejects unsigned tokens."));
        if (alg.StartsWith("HS", StringComparison.OrdinalIgnoreCase))
            findings.Add(new Finding($"Symmetric algorithm ({alg})", Severity.Info, "header",
                "HMAC-signed. If a weak/guessable secret is used it can be brute-forced offline; also watch for RS→HS confusion."));

        using var pdoc = JsonDocument.Parse(parts.PayloadJson);
        var root = pdoc.RootElement;

        if (!root.TryGetProperty("exp", out _))
            findings.Add(new Finding("No 'exp' claim", Severity.Medium, "payload",
                "Token never expires unless the server enforces it elsewhere."));
        else if (root.TryGetProperty("exp", out var exp) && exp.TryGetInt64(out var e))
        {
            var when = DateTimeOffset.FromUnixTimeSeconds(e);
            if (when < DateTimeOffset.UtcNow)
                findings.Add(new Finding("Token is expired", Severity.Info, "payload", $"exp = {when:u}"));
            if (root.TryGetProperty("iat", out var iat) && iat.TryGetInt64(out var i))
            {
                var lifetime = when - DateTimeOffset.FromUnixTimeSeconds(i);
                if (lifetime > TimeSpan.FromDays(30))
                    findings.Add(new Finding("Very long token lifetime", Severity.Low, "payload",
                        $"lifetime ≈ {lifetime.TotalDays:F0} days"));
            }
        }

        foreach (var prop in root.EnumerateObject())
        {
            string name = prop.Name.ToLowerInvariant();
            if (name is "password" or "pwd" or "secret" or "api_key" or "apikey" or "token")
                findings.Add(new Finding($"Sensitive claim '{prop.Name}' in payload", Severity.Medium, "payload",
                    "JWT payloads are only base64 — never a place for secrets."));
        }

        return findings;
    }

    private static byte[] Base64Url(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; }
        return Convert.FromBase64String(s);
    }
}
