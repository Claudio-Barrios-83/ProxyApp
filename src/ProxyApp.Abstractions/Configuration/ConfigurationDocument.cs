namespace ProxyApp.Abstractions.Configuration;

/// <summary>
/// Instantánea completa de la configuración. Es la unidad que se carga, se guarda
/// y se publica al motor: nunca se mutan entidades sueltas en caliente, se
/// reemplaza el documento entero y el motor recompila su índice.
/// </summary>
public sealed record ConfigurationDocument
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    public IReadOnlyList<OutboundNode> Nodes { get; init; } = [];

    public IReadOnlyList<AppRule> Rules { get; init; } = [];

    public EngineSettings Settings { get; init; } = new();

    public static ConfigurationDocument Empty { get; } = new();

    /// <summary>
    /// Valida el documento completo, incluidas las referencias cruzadas entre
    /// reglas y nodos y los ciclos en las cadenas de salida.
    /// </summary>
    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        var nodesById = new Dictionary<Guid, OutboundNode>();

        foreach (var node in Nodes)
        {
            errors.AddRange(node.Validate());

            if (!nodesById.TryAdd(node.Id, node))
            {
                errors.Add($"Identificador de nodo duplicado: {node.Id}.");
            }
        }

        foreach (var node in Nodes.Where(n => n.UpstreamNodeId is not null))
        {
            if (!nodesById.ContainsKey(node.UpstreamNodeId!.Value))
            {
                errors.Add($"'{node.Name}': el nodo anterior {node.UpstreamNodeId} no existe.");
            }
        }

        errors.AddRange(DetectChainCycles(nodesById));

        var ruleIds = new HashSet<Guid>();
        foreach (var rule in Rules)
        {
            errors.AddRange(rule.Validate());

            if (!ruleIds.Add(rule.Id))
            {
                errors.Add($"Identificador de regla duplicado: {rule.Id}.");
            }

            if (rule.OutboundNodeId != Guid.Empty && !nodesById.ContainsKey(rule.OutboundNodeId))
            {
                errors.Add($"'{rule.Name}': apunta a un nodo inexistente ({rule.OutboundNodeId}).");
            }
        }

        errors.AddRange(Settings.Validate());
        return errors;
    }

    private static IEnumerable<string> DetectChainCycles(Dictionary<Guid, OutboundNode> nodesById)
    {
        foreach (var start in nodesById.Values)
        {
            var visited = new HashSet<Guid> { start.Id };
            var current = start;

            while (current.UpstreamNodeId is { } upstreamId && nodesById.TryGetValue(upstreamId, out var upstream))
            {
                if (!visited.Add(upstreamId))
                {
                    yield return $"Ciclo en la cadena de salida que incluye '{start.Name}'.";
                    break;
                }

                current = upstream;
            }
        }
    }
}

/// <summary>Ajustes globales del motor. Ninguno está cableado en el código.</summary>
public sealed record EngineSettings
{
    /// <summary>
    /// Puerto del listener local al que WinDivert redirige las conexiones capturadas.
    /// Con 0 se pide un puerto efímero al arrancar, que es lo recomendable.
    /// </summary>
    public int LocalRedirectPort { get; init; }

    /// <summary>Activa el pool de IPs sintéticas que preserva el FQDN y evita la fuga de DNS.</summary>
    public bool EnableFakeIpDns { get; init; } = true;

    /// <summary>Rango reservado para las IPs sintéticas. 198.18.0.0/15 está asignado a benchmarking.</summary>
    public string FakeIpRange { get; init; } = "198.18.0.0/15";

    /// <summary>
    /// Bloquea UDP/443 de las apps interceptadas para forzar el fallback de QUIC a
    /// TCP mientras UDP ASSOCIATE no esté implementado.
    /// </summary>
    public bool BlockQuicForManagedApps { get; init; } = true;

    /// <summary>Arrancar el motor automáticamente con el servicio.</summary>
    public bool AutoStartEngine { get; init; }

    /// <summary>Prioridad del filtro WinDivert (-1000..1000). Se baja si otra VPN compite por el flujo.</summary>
    public short WinDivertPriority { get; init; }

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();

        if (LocalRedirectPort is < 0 or > 65535)
        {
            errors.Add($"LocalRedirectPort fuera de rango: {LocalRedirectPort}.");
        }

        if (EnableFakeIpDns && string.IsNullOrWhiteSpace(FakeIpRange))
        {
            errors.Add("EnableFakeIpDns requiere un FakeIpRange válido.");
        }

        if (WinDivertPriority is < -1000 or > 1000)
        {
            errors.Add($"WinDivertPriority fuera del rango admitido: {WinDivertPriority}.");
        }

        return errors;
    }
}
