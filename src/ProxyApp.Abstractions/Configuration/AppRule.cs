namespace ProxyApp.Abstractions.Configuration;

/// <summary>Protocolo de transporte al que aplica una regla.</summary>
public enum TransportProtocol
{
    Any = 0,
    Tcp = 1,
    Udp = 2,
}

/// <summary>
/// Vincula un conjunto de ejecutables con un <see cref="OutboundNode"/>.
/// Las reglas se evalúan en orden de <see cref="Priority"/> y gana la primera
/// que casa, igual que en un firewall.
/// </summary>
public sealed record AppRule
{
    public required Guid Id { get; init; }

    /// <summary>Nombre visible, p. ej. "Colaboración vía OCI".</summary>
    public required string Name { get; init; }

    /// <summary>Menor valor se evalúa antes. Permite reordenar por drag &amp; drop en la UI.</summary>
    public int Priority { get; init; }

    public bool IsEnabled { get; init; } = true;

    /// <summary>Qué procesos captura la regla.</summary>
    public required ProcessSelector Process { get; init; }

    /// <summary>Filtro opcional por destino. Si es <c>null</c>, aplica a cualquier destino.</summary>
    public TargetSelector? Target { get; init; }

    /// <summary>Nodo de salida al que se envía el tráfico que casa.</summary>
    public required Guid OutboundNodeId { get; init; }

    /// <summary>
    /// Deja pasar en directo el tráfico hacia rangos privados y loopback.
    /// Evita romper impresoras, NAS y servicios corporativos en LAN.
    /// </summary>
    public bool BypassPrivateNetworks { get; init; } = true;

    /// <summary>
    /// Limita la regla a una sesión de Windows concreta. El motor corre como
    /// LocalSystem y ve todas las sesiones, así que en equipos compartidos esto
    /// es lo que evita que la configuración de un usuario afecte a otro.
    /// <c>null</c> significa "cualquier usuario".
    /// </summary>
    public string? WindowsUserSid { get; init; }

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(Name))
        {
            errors.Add("La regla necesita un nombre.");
        }

        if (Process.Patterns.Count == 0)
        {
            errors.Add($"'{Name}': hay que indicar al menos un patrón de proceso.");
        }

        if (OutboundNodeId == Guid.Empty)
        {
            errors.Add($"'{Name}': falta el nodo de salida.");
        }

        return errors;
    }
}

/// <summary>
/// Selección de procesos. Acepta tanto nombres sueltos ("teams.exe") como rutas
/// completas con comodines, para distinguir dos binarios homónimos.
/// </summary>
public sealed record ProcessSelector
{
    /// <summary>
    /// Patrones con comodines <c>*</c> y <c>?</c>. Ejemplos: <c>teams.exe</c>,
    /// <c>ms-teams.exe</c>, <c>C:\Program Files\Slack\*.exe</c>.
    /// </summary>
    public IReadOnlyList<string> Patterns { get; init; } = [];

    /// <summary>
    /// Comparar contra la ruta completa del ejecutable en lugar del nombre.
    /// Se activa solo si algún patrón contiene un separador de directorio.
    /// </summary>
    public bool MatchFullPath { get; init; }

    /// <summary>
    /// Heredar la regla en los procesos hijo. Imprescindible para apps tipo
    /// Electron, donde el proceso que abre los sockets no es el que lanzas.
    /// </summary>
    public bool IncludeChildProcesses { get; init; } = true;

    public static ProcessSelector ForExecutables(params string[] names) =>
        new() { Patterns = names, MatchFullPath = names.Any(n => n.Contains('\\', StringComparison.Ordinal)) };
}

/// <summary>Filtro opcional sobre el destino de la conexión.</summary>
public sealed record TargetSelector
{
    /// <summary>Patrones de host, p. ej. <c>*.teams.microsoft.com</c>. Requiere conocer el FQDN.</summary>
    public IReadOnlyList<string> HostPatterns { get; init; } = [];

    /// <summary>Rangos en notación CIDR, IPv4 o IPv6.</summary>
    public IReadOnlyList<string> IpRanges { get; init; } = [];

    /// <summary>Puertos o rangos de puertos.</summary>
    public IReadOnlyList<PortRange> Ports { get; init; } = [];

    public TransportProtocol Protocol { get; init; } = TransportProtocol.Any;

    /// <summary>Un selector sin ningún criterio casa con todo.</summary>
    public bool IsEmpty =>
        HostPatterns.Count == 0 && IpRanges.Count == 0 && Ports.Count == 0 && Protocol == TransportProtocol.Any;
}

/// <summary>Rango de puertos inclusivo.</summary>
public readonly record struct PortRange(int From, int To)
{
    /// <summary>Rango de un solo puerto.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Naming",
        "CA1720:Identifier contains type name",
        Justification = "'Single' describe un rango de un único puerto, no el tipo System.Single.")]
    public static PortRange Single(int port) => new(port, port);

    public bool Contains(int port) => port >= From && port <= To;

    /// <summary>Acepta "443" y "8000-8100".</summary>
    public static PortRange Parse(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);

        var separator = value.IndexOf('-', StringComparison.Ordinal);
        if (separator < 0)
        {
            var single = int.Parse(value.Trim(), System.Globalization.CultureInfo.InvariantCulture);
            return Single(single);
        }

        var from = int.Parse(value[..separator].Trim(), System.Globalization.CultureInfo.InvariantCulture);
        var to = int.Parse(value[(separator + 1)..].Trim(), System.Globalization.CultureInfo.InvariantCulture);
        return new PortRange(Math.Min(from, to), Math.Max(from, to));
    }

    public override string ToString() =>
        From == To
            ? From.ToString(System.Globalization.CultureInfo.InvariantCulture)
            : $"{From}-{To}";
}
