using ProxyApp.Abstractions.Configuration;

namespace ProxyApp.Abstractions.Routing;

/// <summary>Qué hacer con una conexión.</summary>
public enum RouteAction
{
    /// <summary>Dejarla pasar sin tocar nada.</summary>
    Direct = 0,

    /// <summary>Secuestrarla hacia el listener local y tunelizarla por el proxy.</summary>
    Proxy = 1,

    /// <summary>Dejarla salir sin proxy, pero forzada por una interfaz concreta.</summary>
    BindAdapter = 2,

    /// <summary>Rechazarla.</summary>
    Block = 3,
}

/// <summary>
/// Resultado de evaluar una conexión. Incluye la cadena completa de nodos
/// resuelta, porque el relay necesita saltar de uno a otro en orden.
/// </summary>
public sealed record RouteDecision
{
    public required RouteAction Action { get; init; }

    /// <summary>Nodo efectivo de salida. <c>null</c> en <see cref="RouteAction.Direct"/>.</summary>
    public OutboundNode? Node { get; init; }

    /// <summary>
    /// Cadena resuelta desde el nodo más cercano al proceso hasta el más externo.
    /// Con un solo salto contiene únicamente <see cref="Node"/>.
    /// </summary>
    public IReadOnlyList<OutboundNode> Chain { get; init; } = [];

    /// <summary>Regla que decidió. <c>null</c> cuando ninguna casó.</summary>
    public AppRule? MatchedRule { get; init; }

    /// <summary>Motivo legible. Va al log y a la columna "Estado" del dashboard.</summary>
    public required string Reason { get; init; }

    public static RouteDecision DirectBecause(string reason, AppRule? rule = null) =>
        new() { Action = RouteAction.Direct, Reason = reason, MatchedRule = rule };

    public static RouteDecision BlockedBy(AppRule rule, OutboundNode node) =>
        new()
        {
            Action = RouteAction.Block,
            Node = node,
            MatchedRule = rule,
            Reason = $"Bloqueado por la regla '{rule.Name}'.",
        };

    public static RouteDecision Through(AppRule rule, IReadOnlyList<OutboundNode> chain)
    {
        ArgumentOutOfRangeException.ThrowIfZero(chain.Count);

        var head = chain[0];
        return new RouteDecision
        {
            Action = head.Kind is OutboundKind.NetworkAdapter ? RouteAction.BindAdapter : RouteAction.Proxy,
            Node = head,
            Chain = chain,
            MatchedRule = rule,
            Reason = chain.Count == 1
                ? $"Regla '{rule.Name}' → {head.Name}."
                : $"Regla '{rule.Name}' → {string.Join(" → ", chain.Select(n => n.Name))}.",
        };
    }
}
