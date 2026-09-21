using System.Net;
using ProxyApp.Abstractions.Configuration;

namespace ProxyApp.Core.Interception;

/// <summary>Resuelve la ruta del ejecutable y el SID a partir de un PID.</summary>
public interface IProcessIdentityResolver
{
    ProcessIdentity? TryResolve(int processId);
}

/// <summary>
/// Resuelve el PID de una conexión ya visible para el sistema. Es el plan B
/// cuando el evento SOCKET todavía no llegó y el SYN no puede esperar más.
/// </summary>
public interface IConnectionPidResolver
{
    bool TryResolve(
        TransportProtocol protocol,
        IPAddress localAddress,
        int localPort,
        IPAddress remoteAddress,
        int remotePort,
        out int processId);
}
