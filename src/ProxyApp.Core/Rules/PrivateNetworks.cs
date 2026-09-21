using System.Net;

namespace ProxyApp.Core.Rules;

/// <summary>
/// Rangos que nunca deben salir por un proxy remoto salvo petición explícita:
/// romperlos deja sin acceso a impresoras, NAS, controladores de dominio y al
/// propio servicio de descubrimiento de la LAN.
/// </summary>
public static class PrivateNetworks
{
    private static readonly CidrRange[] Ranges =
    [
        CidrRange.Parse("10.0.0.0/8"),
        CidrRange.Parse("172.16.0.0/12"),
        CidrRange.Parse("192.168.0.0/16"),
        CidrRange.Parse("127.0.0.0/8"),
        CidrRange.Parse("169.254.0.0/16"),
        CidrRange.Parse("100.64.0.0/10"),
        CidrRange.Parse("224.0.0.0/4"),
        CidrRange.Parse("::1/128"),
        CidrRange.Parse("fc00::/7"),
        CidrRange.Parse("fe80::/10"),
    ];

    public static bool Contains(IPAddress address)
    {
        foreach (var range in Ranges)
        {
            if (range.Contains(address))
            {
                return true;
            }
        }

        return false;
    }
}
