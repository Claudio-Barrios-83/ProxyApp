using System.Net;
using ProxyApp.Abstractions.Configuration;
using ProxyApp.Abstractions.Routing;

namespace ProxyApp.Core.Interception;

/// <summary>
/// Una conexión ya traducida. La conserva el listener local para saber a qué
/// destino real y por qué nodo tiene que abrir el túnel.
/// </summary>
public sealed record InterceptedFlow
{
    public required int ProcessId { get; init; }

    public required string ExecutablePath { get; init; }

    public required IPEndPoint Client { get; init; }

    public required IPEndPoint OriginalDestination { get; init; }

    public required RouteDecision Decision { get; init; }

    public required TransportProtocol Protocol { get; init; }
}

/// <summary>
/// Tabla de traducción indexada por el extremo local de la aplicación
/// (dirección + puerto efímero). Ese par es único mientras el socket vive.
/// </summary>
/// <remarks>
/// La ida y la vuelta comparten la misma clave. Lo que cambia es qué campo del
/// paquete se compara: en la ida es el origen (lo que envió la app) y en la
/// vuelta es el destino (a quién responde el listener).
/// </remarks>
public sealed class NatTable
{
    private readonly object _gate = new();
    private readonly Dictionary<FlowKey, Entry> _byClient = new();

    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _byClient.Count;
            }
        }
    }

    public bool TryGet(TransportProtocol protocol, IPAddress clientAddress, int clientPort, out InterceptedFlow flow)
    {
        lock (_gate)
        {
            if (_byClient.TryGetValue(new FlowKey(protocol, clientAddress, clientPort), out var entry))
            {
                entry.LastSeenUtc = DateTime.UtcNow;
                flow = entry.Flow;
                return true;
            }
        }

        flow = null!;
        return false;
    }

    public void Add(InterceptedFlow flow)
    {
        ArgumentNullException.ThrowIfNull(flow);

        lock (_gate)
        {
            _byClient[new FlowKey(flow.Protocol, flow.Client.Address, flow.Client.Port)] = new Entry
            {
                Flow = flow,
                LastSeenUtc = DateTime.UtcNow,
            };
        }
    }

    public IPEndPoint[] Clients()
    {
        lock (_gate)
        {
            return _byClient.Values.Select(entry => entry.Flow.Client).ToArray();
        }
    }

    public void Remove(TransportProtocol protocol, IPAddress clientAddress, int clientPort)
    {
        lock (_gate)
        {
            _byClient.Remove(new FlowKey(protocol, clientAddress, clientPort));
        }
    }

    /// <summary>Quita flujos sin tráfico reciente. Se llama desde el bucle de captura, no por paquete.</summary>
    public int Sweep(TimeSpan idle, DateTime nowUtc)
    {
        lock (_gate)
        {
            var stale = _byClient.Where(pair => nowUtc - pair.Value.LastSeenUtc >= idle).Select(pair => pair.Key).ToArray();
            foreach (var key in stale)
            {
                _byClient.Remove(key);
            }

            return stale.Length;
        }
    }

    private sealed class Entry
    {
        public required InterceptedFlow Flow { get; init; }

        public DateTime LastSeenUtc { get; set; }
    }

    private readonly record struct FlowKey(TransportProtocol Protocol, IPAddress Address, int Port);
}
