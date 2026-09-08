namespace Toolkit.Core;

/// <summary>Analyzes CORS response headers for classic misconfigurations.</summary>
public static class CorsAnalyzer
{
    /// <summary>
    /// Given the Origin that was sent and the relevant response headers, returns
    /// findings for reflected origins, null-origin trust, and wildcard-with-
    /// credentials — the combinations that turn CORS into a data-exposure bug.
    /// </summary>
    public static List<Finding> Analyze(string sentOrigin, string target, string? acao, string? acac)
    {
        var findings = new List<Finding>();
        bool creds = acac?.Trim().Equals("true", StringComparison.OrdinalIgnoreCase) == true;

        if (acao == null) return findings; // no CORS headers → nothing to say

        if (acao == "*" && creds)
            findings.Add(new Finding("Wildcard ACAO with credentials", Severity.High, target,
                "Access-Control-Allow-Origin: * together with credentials:true is invalid and dangerous.",
                $"ACAO: {acao}\nACAC: {acac}"));

        if (acao.Equals(sentOrigin, StringComparison.OrdinalIgnoreCase) &&
            sentOrigin.Contains("evil", StringComparison.OrdinalIgnoreCase))
            findings.Add(new Finding("Origin reflected without validation", creds ? Severity.High : Severity.Medium, target,
                "The server echoed an arbitrary Origin into Access-Control-Allow-Origin." +
                (creds ? " With credentials:true this exposes authenticated data." : ""),
                $"Sent Origin: {sentOrigin}\nACAO: {acao}\nACAC: {acac}"));

        if (acao.Equals("null", StringComparison.OrdinalIgnoreCase))
            findings.Add(new Finding("null Origin trusted", creds ? Severity.High : Severity.Medium, target,
                "Access-Control-Allow-Origin: null can be reached from sandboxed iframes.",
                $"ACAO: {acao}\nACAC: {acac}"));

        return findings;
    }
}
