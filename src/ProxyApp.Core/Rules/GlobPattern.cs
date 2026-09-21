using System.Text;
using System.Text.RegularExpressions;

namespace ProxyApp.Core.Rules;

/// <summary>
/// Patrón con comodines <c>*</c> y <c>?</c> compilado a expresión regular.
/// Se construye una sola vez al publicar la configuración, nunca por conexión.
/// </summary>
public sealed class GlobPattern
{
    private readonly Regex _regex;

    private GlobPattern(string pattern, Regex regex)
    {
        Pattern = pattern;
        _regex = regex;
    }

    public string Pattern { get; }

    public static GlobPattern Compile(string pattern)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pattern);

        var builder = new StringBuilder("^");
        foreach (var c in pattern.Trim())
        {
            _ = c switch
            {
                '*' => builder.Append(".*"),
                '?' => builder.Append('.'),
                _ => builder.Append(Regex.Escape(c.ToString())),
            };
        }

        builder.Append('$');

        // Los nombres de fichero y de host en Windows no distinguen mayúsculas.
        var regex = new Regex(
            builder.ToString(),
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled,
            TimeSpan.FromMilliseconds(100));

        return new GlobPattern(pattern, regex);
    }

    public bool IsMatch(string value) => !string.IsNullOrEmpty(value) && _regex.IsMatch(value);

    public override string ToString() => Pattern;
}
