namespace Toolkit.Core;

/// <summary>
/// Minimal command-line parser: supports "--key value", "--flag", and bare
/// positional arguments. No external dependency.
/// </summary>
public sealed class Args
{
    private readonly Dictionary<string, string> _named = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _flags = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _positional = new();

    public Args(string[] argv)
    {
        for (int i = 0; i < argv.Length; i++)
        {
            string a = argv[i];
            if (a.StartsWith("--"))
            {
                string key = a[2..];
                if (i + 1 < argv.Length && !argv[i + 1].StartsWith("--"))
                    _named[key] = argv[++i];
                else
                    _flags.Add(key);
            }
            else
            {
                _positional.Add(a);
            }
        }
    }

    public bool Has(string flag) => _flags.Contains(flag) || _named.ContainsKey(flag);
    public string? Get(string key) => _named.TryGetValue(key, out var v) ? v : null;
    public string Get(string key, string fallback) => _named.TryGetValue(key, out var v) ? v : fallback;
    public int GetInt(string key, int fallback) => _named.TryGetValue(key, out var v) && int.TryParse(v, out var n) ? n : fallback;
    public IReadOnlyList<string> Positional => _positional;

    public string Require(string key)
    {
        if (!_named.TryGetValue(key, out var v) || string.IsNullOrWhiteSpace(v))
            throw new ArgumentException($"missing required --{key}");
        return v;
    }
}
