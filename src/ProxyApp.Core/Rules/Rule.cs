using System.Text.Json;
using System.Text.Json.Serialization;
using ProxyApp.Abstractions.Configuration;

namespace ProxyApp.Core.Rules;

/// <summary>Tipo de proxy al que puede apuntar una regla.</summary>
public enum ProxyType
{
    /// <summary>Salida directa, sin proxy.</summary>
    Direct = 0,

    /// <summary>SOCKS5 (RFC 1928).</summary>
    Socks5 = 1,

    /// <summary>Proxy HTTP con CONNECT.</summary>
    Http = 2,

    /// <summary>Salida por un adaptador de Windows, por ejemplo una VPN ya conectada.</summary>
    Adapter = 3,
}

/// <summary>Usuario y contraseña del proxy, en claro y solo en memoria.</summary>
public sealed record ProxyAuth
{
    public required string Username { get; init; }

    public required string Password { get; init; }
}

/// <summary>
/// Destino de una regla. <see cref="Direct"/> es el valor que devuelve el motor
/// cuando ninguna regla aplica o cuando el destino es red local y la regla lo pide.
/// </summary>
public sealed record Proxy
{
    public static Proxy Direct { get; } = new() { Type = ProxyType.Direct };

    public string? Host { get; init; }

    public int Port { get; init; }

    public ProxyType Type { get; init; }

    public ProxyAuth? Auth { get; init; }

    public bool IsDirect => Type == ProxyType.Direct;

    public IReadOnlyList<string> Validate()
    {
        if (IsDirect)
        {
            return [];
        }

        if (Type == ProxyType.Adapter)
        {
            return string.IsNullOrWhiteSpace(Host)
                ? ["Elige la VPN por la que debe salir el programa."]
                : [];
        }

        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(Host))
        {
            errors.Add("El proxy necesita un host.");
        }

        if (Port is <= 0 or > 65535)
        {
            errors.Add($"Puerto de proxy fuera de rango: {Port}.");
        }

        if (Auth is { Username: null or "" })
        {
            errors.Add("La autenticación del proxy necesita un usuario.");
        }

        return errors;
    }
}

/// <summary>
/// Regla que ata un ejecutable (con comodín <c>*</c>) a un proxy.
/// El orden en la lista es la prioridad: gana la primera que casa.
/// </summary>
public sealed record Rule
{
    public required Guid RuleId { get; init; }

    /// <summary>Nombre de ejecutable. Acepta <c>*</c> y <c>?</c>, por ejemplo <c>*teams*.exe</c>.</summary>
    public required string ProcessName { get; init; }

    public required Proxy TargetProxy { get; init; }

    public bool IsEnabled { get; init; } = true;

    /// <summary>
    /// Si es true, el tráfico hacia redes privadas (10.0.0.0/8, 192.168.0.0/16 y el resto
    /// de rangos locales) sale directo aunque el proceso case.
    /// </summary>
    public bool BypassLocalNetwork { get; init; } = true;

    /// <summary>Texto corto para la lista: nombre de VPN, o host y puerto del proxy.</summary>
    public string ExitLabel => TargetProxy.Type == ProxyType.Adapter
        ? TargetProxy.Host ?? ""
        : $"{TargetProxy.Host}:{TargetProxy.Port}";

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        if (RuleId == Guid.Empty)
        {
            errors.Add("RuleId no puede ser vacío.");
        }

        if (string.IsNullOrWhiteSpace(ProcessName))
        {
            errors.Add("ProcessName es obligatorio.");
        }

        if (TargetProxy is null)
        {
            errors.Add("TargetProxy es obligatorio.");
        }
        else
        {
            errors.AddRange(TargetProxy.Validate());
        }

        return errors;
    }

    internal AppRule ToAppRule(int priority) => new()
    {
        Id = RuleId,
        Name = ProcessName,
        Priority = priority,
        IsEnabled = IsEnabled,
        Process = ProcessSelector.ForExecutables(ProcessName),
        OutboundNodeId = RuleId,
        BypassPrivateNetworks = BypassLocalNetwork,
    };

    internal OutboundNode ToNode() => new()
    {
        Id = RuleId,
        Name = ProcessName,
        Kind = TargetProxy.Type switch
        {
            ProxyType.Socks5 => OutboundKind.Socks5,
            ProxyType.Http => OutboundKind.HttpProxy,
            ProxyType.Adapter => OutboundKind.NetworkAdapter,
            _ => OutboundKind.Direct,
        },
        IsEnabled = true,
        Host = TargetProxy.Type == ProxyType.Adapter ? null : TargetProxy.Host,
        Port = TargetProxy.Type == ProxyType.Adapter ? 0 : TargetProxy.Port,
        Adapter = TargetProxy.Type == ProxyType.Adapter
            ? new AdapterBinding { InterfaceName = TargetProxy.Host!.Trim() }
            : null,
        Credentials = TargetProxy.Auth is null
            ? null
            : new ProxyCredentials
            {
                Username = TargetProxy.Auth.Username,
                ProtectedPassword = TargetProxy.Auth.Password,
            },
    };
}

internal static class RuleFile
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public static ConfigurationDocument ToDocument(IReadOnlyList<Rule> rules)
    {
        var errors = new List<string>();
        var ids = new HashSet<Guid>();
        foreach (var rule in rules)
        {
            errors.AddRange(rule.Validate());
            if (!ids.Add(rule.RuleId))
            {
                errors.Add($"RuleId duplicado: {rule.RuleId}.");
            }
        }

        if (errors.Count > 0)
        {
            throw new ArgumentException(string.Join(Environment.NewLine, errors));
        }

        return new ConfigurationDocument
        {
            Nodes = rules.Select(rule => rule.ToNode()).ToArray(),
            Rules = rules.Select((rule, index) => rule.ToAppRule(index)).ToArray(),
        };
    }

    public static Rule[] Read(string path)
    {
        var json = File.ReadAllText(path);
        var file = JsonSerializer.Deserialize<RuleList>(json, Options) ?? new RuleList();
        return file.Rules?.ToArray() ?? [];
    }

    public static void Write(string path, IReadOnlyList<Rule> rules)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var json = JsonSerializer.Serialize(new RuleList { Rules = rules.ToArray() }, Options);
        var temporary = path + ".tmp";
        File.WriteAllText(temporary, json);
        File.Move(temporary, path, overwrite: true);
    }

    private sealed class RuleList
    {
        public Rule[]? Rules { get; init; }
    }
}
