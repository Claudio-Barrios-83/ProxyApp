using System.Net;
using ProxyApp.Abstractions.Configuration;

namespace ProxyApp.Abstractions.Routing;

/// <summary>
/// Conexión saliente detectada por el motor, ya correlacionada con su proceso.
/// Es lo único que necesita el motor de reglas para decidir.
/// </summary>
public sealed record ConnectionRequest
{
    public required int ProcessId { get; init; }

    /// <summary>Ruta completa del ejecutable resuelta desde el PID.</summary>
    public required string ExecutablePath { get; init; }

    public required IPAddress RemoteAddress { get; init; }

    public required int RemotePort { get; init; }

    public TransportProtocol Protocol { get; init; } = TransportProtocol.Tcp;

    /// <summary>
    /// FQDN del destino cuando se conoce (resuelto por la capa de fake-IP o por un
    /// hook de <c>getaddrinfo</c>). Si es <c>null</c> solo se puede filtrar por IP.
    /// </summary>
    public string? RemoteHost { get; init; }

    /// <summary>SID del usuario dueño del proceso. Lo usa el filtrado multiusuario.</summary>
    public string? UserSid { get; init; }

    /// <summary>PID del proceso padre, para heredar reglas en árboles tipo Electron.</summary>
    public int? ParentProcessId { get; init; }

    /// <summary>
    /// Nombre del binario sin ruta. No usa <see cref="Path.GetFileName(string)"/> a
    /// propósito: las rutas llegan siempre con separador de Windows desde
    /// <c>QueryFullProcessImageName</c>, y fuera de Windows esa API no reconoce
    /// la barra invertida, lo que rompería los tests en CI de Linux.
    /// </summary>
    public string ExecutableName
    {
        get
        {
            var separator = ExecutablePath.AsSpan().LastIndexOfAny('\\', '/');
            return separator < 0 ? ExecutablePath : ExecutablePath[(separator + 1)..];
        }
    }
}
