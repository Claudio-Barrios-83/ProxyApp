using System.Net;
using System.Net.Sockets;
using ProxyApp.Abstractions.Configuration;
using ProxyApp.Abstractions.Routing;
using ProxyApp.Core.Rules;

namespace ProxyApp.Core.Interception;

/// <summary>Qué hacer con un paquete ya parseado.</summary>
public enum PacketFate
{
    /// <summary>Reinyectar los bytes originales, sin tocar marcas de dirección.</summary>
    ReinjectUnchanged = 0,

    /// <summary>Los extremos ya están reescritos en el buffer. Hay que recalcular checksums.</summary>
    ReinjectModified = 1,

    /// <summary>No reinyectar. El SYN descartado hace fallar el connect por timeout.</summary>
    Drop = 2,

    /// <summary>El PID todavía no llegó de la capa SOCKET. Conservar el paquete y reintentar.</summary>
    Hold = 3,
}

/// <summary>Plan de reinyección. Los extremos nulos significan "no cambiar ese campo".</summary>
public readonly record struct PacketPlan(
    PacketFate Fate,
    IPAddress? NewSource,
    int? NewSourcePort,
    IPAddress? NewDestination,
    int? NewDestinationPort,
    bool InjectInbound,
    bool MarkLoopback)
{
    public static PacketPlan Unchanged { get; } = new(PacketFate.ReinjectUnchanged, null, null, null, null, false, false);

    public static PacketPlan Drop { get; } = new(PacketFate.Drop, null, null, null, null, false, false);

    public static PacketPlan Hold { get; } = new(PacketFate.Hold, null, null, null, null, false, false);
}

/// <summary>Identidad de un proceso, resuelta una vez y cacheada por el host de Windows.</summary>
public readonly record struct ProcessIdentity(string ExecutablePath, string? UserSid);

/// <summary>
/// Decide la traducción de cada paquete. No abre handles ni recalcula checksums:
/// eso es trabajo de <c>ProcessNetworkFilter</c>, y así esta clase se puede
/// probar sin el driver.
/// </summary>
public sealed class PacketPipeline
{
    private readonly RoutingRuleEngine _rules;
    private readonly IPEndPoint _tcpRedirect;
    private readonly IPEndPoint? _udpRelay;
    private readonly int _engineProcessId;
    private readonly bool _blockQuic;
    private readonly Func<IReadOnlyList<IPEndPoint>>? _passthroughEndpoints;
    private readonly TimeSpan _flowIdle;

    public PacketPipeline(
        RoutingRuleEngine rules,
        IPEndPoint tcpRedirect,
        int engineProcessId,
        bool blockQuic = true,
        IPEndPoint? udpRelay = null,
        Func<IReadOnlyList<IPEndPoint>>? passthroughEndpoints = null,
        TimeSpan? flowIdle = null)
    {
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(tcpRedirect);

        if (tcpRedirect.Address.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new ArgumentException("El listener de redirección tiene que ser IPv4.", nameof(tcpRedirect));
        }

        if (tcpRedirect.Port is <= 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(tcpRedirect), "El puerto de redirección todavía no está enlazado.");
        }

        _rules = rules;
        _tcpRedirect = new IPEndPoint(tcpRedirect.Address, tcpRedirect.Port);
        _udpRelay = udpRelay is null ? null : new IPEndPoint(udpRelay.Address, udpRelay.Port);
        _engineProcessId = engineProcessId;
        _blockQuic = blockQuic;
        _passthroughEndpoints = passthroughEndpoints;
        _flowIdle = flowIdle ?? TimeSpan.FromMinutes(2);
        Flows = new NatTable();
    }

    public NatTable Flows { get; }

    public IPEndPoint TcpRedirect => _tcpRedirect;

    /// <summary>
    /// Clasifica un paquete saliente. <paramref name="resolvePid"/> devuelve null
    /// cuando ni la capa SOCKET ni la tabla TCP conocen todavía la conexión.
    /// </summary>
    public PacketPlan Decide(
        ParsedIpv4Packet packet,
        Func<int?> resolvePid,
        Func<int, ProcessIdentity?> resolveIdentity)
    {
        ArgumentNullException.ThrowIfNull(resolvePid);
        ArgumentNullException.ThrowIfNull(resolveIdentity);

        // Paquete generado por nuestro listener aceptando la conexión de la app.
        // Hay que deshacer la traducción para que la TCB de la app, indexada por
        // el destino original, acepte el segmento.
        if (IsFromRedirector(packet))
        {
            return Reverse(packet);
        }

        if (Flows.TryGet(packet.Protocol, packet.Source, packet.SourcePort, out var existing))
        {
            // RST mata la TCB. FIN no: todavía falta el ACK del cierre y, si
            // borramos la entrada aquí, ese ACK saldría sin traducir.
            if (packet.Rst)
            {
                Flows.Remove(packet.Protocol, packet.Source, packet.SourcePort);
            }

            return Forward(existing);
        }

        var pid = resolvePid();
        if (pid is null)
        {
            // Solo el primer segmento se retiene. Un ACK suelto sin estado ya
            // pertenece a una conexión que no vimos nacer: dejarlo pasar es
            // mejor que congelar tráfico que no podemos secuestrar.
            return packet.IsInitialSyn || packet.Protocol == TransportProtocol.Udp
                ? PacketPlan.Hold
                : PacketPlan.Unchanged;
        }

        if (pid.Value == _engineProcessId || IsPassthrough(packet))
        {
            return PacketPlan.Unchanged;
        }

        var identity = resolveIdentity(pid.Value);
        if (identity is null)
        {
            return PacketPlan.Unchanged;
        }

        var decision = _rules.Evaluate(new ConnectionRequest
        {
            ProcessId = pid.Value,
            ExecutablePath = identity.Value.ExecutablePath,
            RemoteAddress = packet.Destination,
            RemotePort = packet.DestinationPort,
            Protocol = packet.Protocol,
            UserSid = identity.Value.UserSid,
        });

        return decision.Action switch
        {
            RouteAction.Direct => PacketPlan.Unchanged,
            RouteAction.Block => PacketPlan.Drop,
            // Proxy y adaptador se desvían al listener. El socket de salida, no el de la
            // aplicación, es el que se ata a la VPN. El resto del sistema no cambia de ruta.
            RouteAction.Proxy or RouteAction.BindAdapter => Proxy(packet, pid.Value, identity.Value, decision),
            _ => PacketPlan.Unchanged,
        };
    }

    public int Sweep(DateTime nowUtc) => Flows.Sweep(_flowIdle, nowUtc);

    private PacketPlan Proxy(
        ParsedIpv4Packet packet,
        int processId,
        ProcessIdentity identity,
        RouteDecision decision)
    {
        if (packet.Protocol == TransportProtocol.Udp)
        {
            if (_blockQuic && packet.DestinationPort == 443 && decision.Node?.SupportsUdpAssociate != true)
            {
                // QUIC no habla con el listener TCP. Tirar UDP/443 obliga a la
                // aplicación a reintentar por TCP, que sí secuestramos.
                return PacketPlan.Drop;
            }

            if (_udpRelay is null || decision.Node?.SupportsUdpAssociate != true)
            {
                // Traducir UDP hacia un socket TCP lo haría desaparecer. Hasta
                // que exista el relay de UDP ASSOCIATE, ese tráfico sale directo.
                return PacketPlan.Unchanged;
            }
        }

        var redirect = packet.Protocol == TransportProtocol.Tcp ? _tcpRedirect : _udpRelay!;

        Flows.Add(new InterceptedFlow
        {
            ProcessId = processId,
            ExecutablePath = identity.ExecutablePath,
            Client = new IPEndPoint(packet.Source, packet.SourcePort),
            OriginalDestination = new IPEndPoint(packet.Destination, packet.DestinationPort),
            Decision = decision,
            Protocol = packet.Protocol,
        });

        // Solo se reescribe el destino. El origen se queda con la IP real de la
        // app para que accept() del listener vea quién conectó y para que la
        // TCB siga indexada por esa IP local. Marcarlo loopback evita que el
        // segmento, ya dirigido a 127.0.0.1, salga por la NIC.
        return new PacketPlan(
            PacketFate.ReinjectModified,
            NewSource: null,
            NewSourcePort: null,
            NewDestination: redirect.Address,
            NewDestinationPort: redirect.Port,
            InjectInbound: false,
            MarkLoopback: true);
    }

    private PacketPlan Reverse(ParsedIpv4Packet packet)
    {
        if (!Flows.TryGet(packet.Protocol, packet.Destination, packet.DestinationPort, out var flow))
        {
            return PacketPlan.Unchanged;
        }

        if (packet.Rst)
        {
            Flows.Remove(packet.Protocol, packet.Destination, packet.DestinationPort);
        }

        // El listener responde desde 127.0.0.1:puerto-redirect. La app espera
        // el segmento desde el servidor real y por el lado entrante de la pila.
        // Reinyectarlo como saliente lo mandaría a la NIC en vez de a la TCB.
        return new PacketPlan(
            PacketFate.ReinjectModified,
            NewSource: flow.OriginalDestination.Address,
            NewSourcePort: flow.OriginalDestination.Port,
            NewDestination: null,
            NewDestinationPort: null,
            InjectInbound: true,
            MarkLoopback: false);
    }

    private PacketPlan Forward(InterceptedFlow flow)
    {
        var redirect = flow.Protocol == TransportProtocol.Tcp ? _tcpRedirect : _udpRelay;
        if (redirect is null)
        {
            return PacketPlan.Unchanged;
        }

        return new PacketPlan(
            PacketFate.ReinjectModified,
            null,
            null,
            redirect.Address,
            redirect.Port,
            InjectInbound: false,
            MarkLoopback: true);
    }

    private bool IsFromRedirector(ParsedIpv4Packet packet)
    {
        if (packet.Protocol == TransportProtocol.Tcp &&
            packet.Source.Equals(_tcpRedirect.Address) &&
            packet.SourcePort == _tcpRedirect.Port)
        {
            return true;
        }

        return _udpRelay is not null &&
               packet.Protocol == TransportProtocol.Udp &&
               packet.Source.Equals(_udpRelay.Address) &&
               packet.SourcePort == _udpRelay.Port;
    }

    private bool IsPassthrough(ParsedIpv4Packet packet)
    {
        if (_passthroughEndpoints is null)
        {
            return false;
        }

        foreach (var endpoint in _passthroughEndpoints())
        {
            if (endpoint.Port == packet.DestinationPort && endpoint.Address.Equals(packet.Destination))
            {
                return true;
            }
        }

        return false;
    }
}
