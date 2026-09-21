using System.Net;
using ProxyApp.Abstractions.Configuration;

namespace ProxyApp.Core.Interception;

/// <summary>
/// Mapa de la 4-tupla de un socket al PID que lo abrió.
/// </summary>
/// <remarks>
/// La capa NETWORK de WinDivert no trae el PID. La capa SOCKET sí, en el evento
/// CONNECT, pero no está garantizado que ese evento llegue antes que el SYN.
/// Por eso el primer SYN sin PID se retiene unos milisegundos en vez de
/// reenviarse al destino real: si se reenvía, el handshake ya no se puede
/// secuestrar.
/// </remarks>
public sealed class SocketProcessMap
{
    private readonly object _gate = new();
    private readonly Dictionary<SocketKey, int> _pids = new();

    public void Connected(
        TransportProtocol protocol,
        IPAddress localAddress,
        int localPort,
        IPAddress remoteAddress,
        int remotePort,
        int processId)
    {
        if (localPort == 0 || processId <= 0)
        {
            return;
        }

        lock (_gate)
        {
            _pids[new SocketKey(protocol, localAddress, localPort, remoteAddress, remotePort)] = processId;
        }
    }

    public void Closed(
        TransportProtocol protocol,
        IPAddress localAddress,
        int localPort,
        IPAddress remoteAddress,
        int remotePort)
    {
        lock (_gate)
        {
            _pids.Remove(new SocketKey(protocol, localAddress, localPort, remoteAddress, remotePort));
        }
    }

    public bool TryGet(
        TransportProtocol protocol,
        IPAddress localAddress,
        int localPort,
        IPAddress remoteAddress,
        int remotePort,
        out int processId)
    {
        lock (_gate)
        {
            return _pids.TryGetValue(new SocketKey(protocol, localAddress, localPort, remoteAddress, remotePort), out processId);
        }
    }

    private readonly record struct SocketKey(
        TransportProtocol Protocol,
        IPAddress LocalAddress,
        int LocalPort,
        IPAddress RemoteAddress,
        int RemotePort);
}
