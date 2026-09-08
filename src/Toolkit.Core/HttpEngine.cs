using System.Diagnostics;

namespace Toolkit.Core;

/// <summary>The outcome of a single HTTP request, normalized for analysis.</summary>
public sealed record HttpResult(
    int Status,
    string Reason,
    Dictionary<string, string> Headers,
    string Body,
    long ElapsedMs,
    Uri RequestUrl)
{
    public string? Header(string name) =>
        Headers.TryGetValue(name, out var v) ? v : null;
}

/// <summary>
/// A thin wrapper over HttpClient tuned for security testing: redirects are OFF
/// by default (so you can inspect them yourself), TLS validation can be relaxed
/// for lab targets, and every response comes back fully materialized.
/// </summary>
public sealed class HttpEngine : IDisposable
{
    private readonly HttpClient _client;

    public HttpEngine(int timeoutMs = 15000, bool allowRedirects = false, bool insecureTls = false)
    {
        var handler = new HttpClientHandler { AllowAutoRedirect = allowRedirects };
        if (insecureTls)
            handler.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

        _client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(timeoutMs) };
        _client.DefaultRequestHeaders.UserAgent.ParseAdd("bugbounty-toolkit/1.0 (authorized-testing)");
    }

    public async Task<HttpResult> SendAsync(
        string method, string url,
        IDictionary<string, string>? headers = null, string? body = null)
    {
        using var req = new HttpRequestMessage(new HttpMethod(method), url);
        if (headers != null)
            foreach (var (k, v) in headers)
            {
                if (!req.Headers.TryAddWithoutValidation(k, v))
                    req.Content ??= new StringContent("");
            }
        if (body != null)
            req.Content = new StringContent(body);

        var sw = Stopwatch.StartNew();
        using var resp = await _client.SendAsync(req, HttpCompletionOption.ResponseContentRead);
        string text = await resp.Content.ReadAsStringAsync();
        sw.Stop();

        var merged = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in resp.Headers) merged[h.Key] = string.Join(", ", h.Value);
        foreach (var h in resp.Content.Headers) merged[h.Key] = string.Join(", ", h.Value);

        return new HttpResult(
            (int)resp.StatusCode,
            resp.ReasonPhrase ?? "",
            merged,
            text,
            sw.ElapsedMilliseconds,
            req.RequestUri!);
    }

    public void Dispose() => _client.Dispose();
}
