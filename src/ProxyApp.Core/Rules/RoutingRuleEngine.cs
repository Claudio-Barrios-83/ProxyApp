using System.Net;
using ProxyApp.Abstractions.Configuration;
using ProxyApp.Abstractions.Routing;

namespace ProxyApp.Core.Rules;

/// <summary>
/// Evalúa cada conexión contra el conjunto de reglas y devuelve por dónde debe salir.
/// </summary>
/// <remarks>
/// Se llama una vez por conexión desde el bucle de WinDivert, así que el camino
/// caliente no hace parsing, ni asignaciones evitables, ni toma locks: toda la
/// configuración se precompila en un <see cref="Snapshot"/> inmutable y
/// <see cref="Publish"/> lo reemplaza con una escritura atómica de referencia.
/// </remarks>
public sealed class RoutingRuleEngine
{
    private volatile EngineState _state = EngineState.Empty;

    public RoutingRuleEngine()
    {
    }

    public RoutingRuleEngine(ConfigurationDocument document) => Publish(document);

    public RoutingRuleEngine(IReadOnlyList<Rule> rules) => ReplaceRules(rules);

    /// <summary>Reemplaza la configuración activa. Las conexiones en curso no se ven afectadas.</summary>
    public void Publish(ConfigurationDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        var current = _state;
        _state = new EngineState(Snapshot.Build(document), current.Rules);
    }

    /// <summary>Sustituye el conjunto de reglas de la API simple y recompila el motor.</summary>
    public void ReplaceRules(IReadOnlyList<Rule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        var materialized = rules.ToArray();
        _state = new EngineState(Snapshot.Build(RuleFile.ToDocument(materialized)), materialized);
    }

    /// <summary>Número de reglas activas. Lo consume el dashboard.</summary>
    public int ActiveRuleCount => _state.Snapshot.Rules.Length;

    /// <summary>Copia activa de las reglas de la API simple, en el orden de prioridad.</summary>
    public IReadOnlyList<Rule> Rules => _state.Rules;

    /// <summary>
    /// Devuelve el proxy de la primera regla que casa con el ejecutable y el destino.
    /// Si ninguna aplica, o el destino es red local y la regla lo omite, devuelve <see cref="Proxy.Direct"/>.
    /// </summary>
    public Proxy GetProxyForProcess(string processName, string targetIp, int targetPort)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(processName);
        if (targetPort is <= 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(targetPort));
        }

        if (!IPAddress.TryParse(targetIp, out var address))
        {
            throw new ArgumentException($"IP de destino no válida: '{targetIp}'.", nameof(targetIp));
        }

        var state = _state;
        var decision = Evaluate(state.Snapshot, new ConnectionRequest
        {
            ProcessId = 0,
            ExecutablePath = processName,
            RemoteAddress = address,
            RemotePort = targetPort,
        });

        if (decision.Action is not (RouteAction.Proxy or RouteAction.BindAdapter) || decision.MatchedRule is null)
        {
            return Proxy.Direct;
        }

        foreach (var rule in state.Rules)
        {
            if (rule.RuleId == decision.MatchedRule.Id)
            {
                return rule.TargetProxy;
            }
        }

        return Proxy.Direct;
    }

    /// <summary>Carga reglas desde JSON y las deja activas.</summary>
    public void LoadRulesFromJson(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ReplaceRules(RuleFile.Read(path));
    }

    /// <summary>Guarda el conjunto de reglas actual. La escritura es atómica.</summary>
    public void SaveRulesToJson(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        RuleFile.Write(path, _state.Rules);
    }

    public RouteDecision Evaluate(ConnectionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return Evaluate(_state.Snapshot, request);
    }

    private static RouteDecision Evaluate(Snapshot snapshot, ConnectionRequest request)
    {
        if (snapshot.Rules.Length == 0)
        {
            return RouteDecision.DirectBecause("No hay reglas activas.");
        }

        foreach (var rule in snapshot.Rules)
        {
            if (!MatchesUser(rule, request) || !MatchesProcess(rule, request) || !MatchesTarget(rule, request))
            {
                continue;
            }

            if (rule.Source.BypassPrivateNetworks && PrivateNetworks.Contains(request.RemoteAddress))
            {
                return RouteDecision.DirectBecause(
                    $"Regla '{rule.Source.Name}' casa, pero {request.RemoteAddress} es red privada.",
                    rule.Source);
            }

            if (!snapshot.NodesById.TryGetValue(rule.Source.OutboundNodeId, out var node))
            {
                // La validación del documento debería impedirlo; si llega aquí,
                // fallar abierto es preferible a cortarle la red al usuario.
                return RouteDecision.DirectBecause(
                    $"Regla '{rule.Source.Name}' apunta a un nodo inexistente.",
                    rule.Source);
            }

            if (!node.IsEnabled)
            {
                return RouteDecision.DirectBecause(
                    $"El nodo '{node.Name}' está desactivado.",
                    rule.Source);
            }

            return node.Kind switch
            {
                OutboundKind.Direct => RouteDecision.DirectBecause($"Regla '{rule.Source.Name}' → salida directa.", rule.Source),
                OutboundKind.Block => RouteDecision.BlockedBy(rule.Source, node),
                _ => RouteDecision.Through(rule.Source, ResolveChain(snapshot, node)),
            };
        }

        return RouteDecision.DirectBecause("Ninguna regla casa con la conexión.");
    }

    private static List<OutboundNode> ResolveChain(Snapshot snapshot, OutboundNode head)
    {
        var chain = new List<OutboundNode> { head };
        var current = head;

        // La validación del documento ya descartó ciclos, pero el motor no confía
        // en datos que pueden venir de un JSON editado a mano.
        while (current.UpstreamNodeId is { } upstreamId &&
               chain.Count < Snapshot.MaxChainDepth &&
               snapshot.NodesById.TryGetValue(upstreamId, out var upstream) &&
               !chain.Contains(upstream))
        {
            chain.Add(upstream);
            current = upstream;
        }

        return chain;
    }

    private static bool MatchesUser(CompiledRule rule, ConnectionRequest request) =>
        rule.Source.WindowsUserSid is null ||
        string.Equals(rule.Source.WindowsUserSid, request.UserSid, StringComparison.OrdinalIgnoreCase);

    private static bool MatchesProcess(CompiledRule rule, ConnectionRequest request)
    {
        var candidate = rule.Source.Process.MatchFullPath ? request.ExecutablePath : request.ExecutableName;

        foreach (var pattern in rule.ProcessPatterns)
        {
            if (pattern.IsMatch(candidate))
            {
                return true;
            }
        }

        return false;
    }

    private static bool MatchesTarget(CompiledRule rule, ConnectionRequest request)
    {
        var target = rule.Source.Target;
        if (target is null || target.IsEmpty)
        {
            return true;
        }

        if (target.Protocol != TransportProtocol.Any && target.Protocol != request.Protocol)
        {
            return false;
        }

        if (rule.Ports.Length > 0 && !rule.Ports.Any(p => p.Contains(request.RemotePort)))
        {
            return false;
        }

        // Host e IP son alternativas, no requisitos acumulativos: basta con que el
        // destino case por cualquiera de las dos vías.
        var hasAddressCriteria = rule.HostPatterns.Length > 0 || rule.IpRanges.Length > 0;
        if (!hasAddressCriteria)
        {
            return true;
        }

        if (request.RemoteHost is { } host && rule.HostPatterns.Any(p => p.IsMatch(host)))
        {
            return true;
        }

        return rule.IpRanges.Any(r => r.Contains(request.RemoteAddress));
    }

    private sealed class EngineState
    {
        public EngineState(Snapshot snapshot, Rule[] rules)
        {
            Snapshot = snapshot;
            Rules = rules;
        }

        public static EngineState Empty { get; } = new(Snapshot.Empty, []);

        public Snapshot Snapshot { get; }

        public Rule[] Rules { get; }
    }

    /// <summary>Configuración precompilada e inmutable.</summary>
    private sealed class Snapshot
    {
        internal const int MaxChainDepth = 8;

        public static Snapshot Empty { get; } = new()
        {
            Rules = [],
            NodesById = new Dictionary<Guid, OutboundNode>(),
        };

        public required CompiledRule[] Rules { get; init; }

        public required Dictionary<Guid, OutboundNode> NodesById { get; init; }

        public static Snapshot Build(ConfigurationDocument document)
        {
            var rules = document.Rules
                .Where(r => r.IsEnabled)
                .OrderBy(r => r.Priority)
                .ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
                .Select(CompiledRule.From)
                .ToArray();

            var nodes = new Dictionary<Guid, OutboundNode>();
            foreach (var node in document.Nodes)
            {
                nodes[node.Id] = node;
            }

            return new Snapshot { Rules = rules, NodesById = nodes };
        }
    }

    private sealed class CompiledRule
    {
        public required AppRule Source { get; init; }

        public required GlobPattern[] ProcessPatterns { get; init; }

        public required GlobPattern[] HostPatterns { get; init; }

        public required CidrRange[] IpRanges { get; init; }

        public required PortRange[] Ports { get; init; }

        public static CompiledRule From(AppRule rule) => new()
        {
            Source = rule,
            ProcessPatterns = rule.Process.Patterns.Select(GlobPattern.Compile).ToArray(),
            HostPatterns = rule.Target?.HostPatterns.Select(GlobPattern.Compile).ToArray() ?? [],
            IpRanges = rule.Target?.IpRanges
                .Select(r => CidrRange.TryParse(r, out var parsed) ? parsed : null)
                .OfType<CidrRange>()
                .ToArray() ?? [],
            Ports = rule.Target?.Ports.ToArray() ?? [],
        };
    }
}
