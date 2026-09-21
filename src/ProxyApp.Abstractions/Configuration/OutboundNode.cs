namespace ProxyApp.Abstractions.Configuration;

/// <summary>
/// Tipo de salida que representa un <see cref="OutboundNode"/>.
/// </summary>
public enum OutboundKind
{
    /// <summary>Salida normal del sistema, sin intercepción.</summary>
    Direct = 0,

    /// <summary>La conexión se rechaza antes de establecerse.</summary>
    Block = 1,

    /// <summary>Proxy SOCKS5 (RFC 1928).</summary>
    Socks5 = 2,

    /// <summary>Proxy HTTP con CONNECT (RFC 7231 §4.3.6).</summary>
    HttpProxy = 3,

    /// <summary>
    /// Enlace directo a una interfaz de red concreta (WireGuard, TAP, NIC física).
    /// La conexión sale sin proxy pero forzada por ese adaptador.
    /// </summary>
    NetworkAdapter = 4,
}

/// <summary>
/// Destino de salida configurable. Es la única fuente de verdad sobre "por dónde"
/// sale el tráfico: la UI crea instancias de esta entidad y el motor nunca conoce
/// hosts ni puertos literales.
/// </summary>
public sealed record OutboundNode
{
    /// <summary>Identificador estable. Las reglas referencian este valor, no el nombre.</summary>
    public required Guid Id { get; init; }

    /// <summary>Nombre visible en la UI, p. ej. "OCI Frankfurt" o "WireGuard corporativo".</summary>
    public required string Name { get; init; }

    public required OutboundKind Kind { get; init; }

    public bool IsEnabled { get; init; } = true;

    /// <summary>Host del proxy. Solo aplica a <see cref="OutboundKind.Socks5"/> y <see cref="OutboundKind.HttpProxy"/>.</summary>
    public string? Host { get; init; }

    /// <summary>Puerto del proxy. Solo aplica a los tipos de proxy.</summary>
    public int Port { get; init; }

    /// <summary>Credenciales opcionales. La contraseña viaja siempre cifrada con DPAPI.</summary>
    public ProxyCredentials? Credentials { get; init; }

    /// <summary>
    /// Enviar el FQDN al proxy en lugar de la IP ya resuelta (ATYP 0x03 en SOCKS5).
    /// Desactivarlo provoca fuga de DNS, así que el valor por defecto es <c>true</c>.
    /// </summary>
    public bool ResolveHostnamesRemotely { get; init; } = true;

    /// <summary>Indica si el servidor soporta UDP ASSOCIATE. Necesario para el tráfico de media en tiempo real.</summary>
    public bool SupportsUdpAssociate { get; init; }

    /// <summary>Enlace a interfaz. Solo aplica a <see cref="OutboundKind.NetworkAdapter"/>.</summary>
    public AdapterBinding? Adapter { get; init; }

    /// <summary>
    /// Encadenamiento: alcanzar este nodo a través de otro. El caso típico es un
    /// SOCKS5 cuyo tráfico de salida debe ir forzosamente por el adaptador WireGuard,
    /// sin que eso afecte al resto del sistema.
    /// </summary>
    public Guid? UpstreamNodeId { get; init; }

    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Indica si el nodo necesita <see cref="Host"/> y <see cref="Port"/>.</summary>
    public bool IsProxy => Kind is OutboundKind.Socks5 or OutboundKind.HttpProxy;

    /// <summary>
    /// Valida las invariantes que dependen del <see cref="Kind"/>. El modelo es plano
    /// a propósito para que serialice sin discriminadores, de modo que la coherencia
    /// se comprueba aquí y en el momento de guardar.
    /// </summary>
    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(Name))
        {
            errors.Add("El nodo necesita un nombre.");
        }

        if (IsProxy)
        {
            if (string.IsNullOrWhiteSpace(Host))
            {
                errors.Add($"'{Name}': un nodo {Kind} requiere Host.");
            }

            if (Port is <= 0 or > 65535)
            {
                errors.Add($"'{Name}': puerto {Port} fuera de rango.");
            }
        }

        if (Kind is OutboundKind.NetworkAdapter && Adapter is null)
        {
            errors.Add($"'{Name}': un nodo NetworkAdapter requiere un AdapterBinding.");
        }

        if (Credentials is not null && Kind is OutboundKind.Direct or OutboundKind.Block or OutboundKind.NetworkAdapter)
        {
            errors.Add($"'{Name}': el tipo {Kind} no admite credenciales.");
        }

        if (UpstreamNodeId == Id)
        {
            errors.Add($"'{Name}': un nodo no puede encadenarse consigo mismo.");
        }

        return errors;
    }
}

/// <summary>
/// Credenciales de proxy. La contraseña nunca se persiste en claro: el store la
/// cifra con DPAPI en ámbito de máquina antes de escribirla.
/// </summary>
public sealed record ProxyCredentials
{
    public required string Username { get; init; }

    /// <summary>Contraseña cifrada con DPAPI y codificada en Base64.</summary>
    public required string ProtectedPassword { get; init; }
}

/// <summary>Cómo localizar la interfaz de red en tiempo de ejecución.</summary>
public enum AdapterResolution
{
    /// <summary>Por nombre de interfaz. Resistente a reinicios.</summary>
    ByName = 0,

    /// <summary>Por LUID. Estable mientras la interfaz exista.</summary>
    ByLuid = 1,

    /// <summary>Por índice fijo. Rápido, pero el índice cambia al recrear la interfaz.</summary>
    ByIndex = 2,
}

/// <summary>
/// Enlace a una interfaz de red concreta.
/// </summary>
/// <remarks>
/// El índice de interfaz de Windows no es estable: WireGuard y los adaptadores TAP
/// se recrean al reconectar y reciben un índice nuevo. Por eso el valor persistido
/// por defecto es el nombre y el índice se resuelve justo antes de aplicar
/// <c>IP_UNICAST_IF</c> sobre el socket.
/// </remarks>
public sealed record AdapterBinding
{
    /// <summary>Nombre de la interfaz tal y como lo expone Windows, p. ej. "wg-corp".</summary>
    public required string InterfaceName { get; init; }

    /// <summary>Último índice conocido. Se refresca en cada arranque del motor.</summary>
    public uint? InterfaceIndex { get; init; }

    /// <summary>LUID de la interfaz, si se prefiere una resolución más estable que el nombre.</summary>
    public ulong? InterfaceLuid { get; init; }

    public AdapterResolution Resolution { get; init; } = AdapterResolution.ByName;
}
