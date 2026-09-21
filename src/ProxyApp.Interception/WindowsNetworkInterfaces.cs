using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ProxyApp.Interception;

/// <summary>Un adaptador de red tal como lo ve Windows.</summary>
public sealed record NetworkInterfaceChoice(string Name, string Description, uint Index, bool IsUp)
{
    public string Label
    {
        get
        {
            var same = string.IsNullOrWhiteSpace(Description)
                || string.Equals(Name, Description, StringComparison.OrdinalIgnoreCase);
            var title = same ? Name : $"{Name} — {Description}";
            return IsUp ? $"{title} (conectada)" : $"{title} (desconectada)";
        }
    }
}

/// <summary>
/// Enumera las VPN y túneles (WireGuard, Cisco, FortiClient y el resto) y
/// permite atar un socket de salida a uno de ellos con IP_UNICAST_IF.
/// </summary>
[SupportedOSPlatform("windows")]
public static class WindowsNetworkInterfaces
{
    private const uint AddressFamilyInet = 2;
    private const uint SkipNoise = 0x0002 | 0x0004 | 0x0008 | 0x0100;
    private const uint BufferOverflow = 111;
    private const int LoopbackType = 24;
    private const int TunnelType = 131;
    private const int UnicastInterface = 31;
    private const int DescriptionOffset = 64;
    private const int FriendlyNameOffset = 72;
    private const int IfTypeOffset = 100;
    private const int OperStatusOffset = 104;

    private static readonly string[] VpnHints =
    [
        "wireguard", "wintun", "cisco", "anyconnect", "secure client", "forti", "fortinet",
        "openvpn", "tap-windows", "vpn", "tunnel", "pangp", "globalprotect", "zscaler",
        "pulse", "juniper", "sonicwall", "tailscale", "zerotier", "netmotion",
        "proton", "nordlynx", "nordvpn", "expressvpn", "surfshark", "mullvad", "windscribe",
        "private internet", "cloudflare", "warp", "amnezia", "outline", "ivpn", "mozilla",
        "cyberghost", "purevpn", "hotspot shield", "tunnelbear", "psiphon", "hide.me", "atlas",
    ];

    private static readonly string[] Noise =
    [
        "teredo", "isatap", "6to4", "iphttps", "wan miniport", "wi-fi direct", "wifi direct",
        "bluetooth", "kernel debug", "qos packet", "virtualbox", "vmware", "vethernet",
        "hyper-v", "wsl", "default switch", "npcap", "winpcap", "loopback",
        "lightweight filter", "ndis filter", "wfp", "filter driver", "microsoft wi-fi",
        "intel(r) wi-fi", "intel(r) ethernet", "realtek", "killer ethernet", "npcap loopback",
    ];

    private static readonly string[] StrongVpn =
    [
        "wireguard", "wintun", "proton", "anyconnect", "secure client", "forticlient",
        "ssl vpn", "virtual ethernet", "tap-windows", "openvpn", "pangp", "globalprotect",
        "zscaler", "nordlynx", "nordvpn", "mullvad", "tailscale", "zerotier", "cloudflare",
        "warp", "amnezia", "expressvpn", "surfshark",
    ];

    public static IReadOnlyList<NetworkInterfaceChoice> ListVpn()
    {
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess)
        {
            return [];
        }

        var all = Read();
        var vpn = all.Where(item => IsVpn(item.Name, item.Description, item.IfType)).ToArray();
        var chosen = vpn.Length > 0 ? vpn : all.ToArray();
        return chosen
            .Select(item => new NetworkInterfaceChoice(item.Name, item.Description, item.Index, item.Up))
            .OrderByDescending(item => item.IsUp)
            .ThenBy(item => item.Label, StringComparer.CurrentCultureIgnoreCase)
            .ToArray();
    }

    public static uint? TryGetIndex(string interfaceName)
    {
        if (string.IsNullOrWhiteSpace(interfaceName) || !OperatingSystem.IsWindows())
        {
            return null;
        }

        foreach (var item in Read())
        {
            if (string.Equals(item.Name, interfaceName, StringComparison.OrdinalIgnoreCase)
                || string.Equals(item.Description, interfaceName, StringComparison.OrdinalIgnoreCase))
            {
                return item.Index;
            }
        }

        return null;
    }

    public static void Bind(Socket socket, uint interfaceIndex)
    {
        ArgumentNullException.ThrowIfNull(socket);
        var ordered = IPAddressNetworkOrder(interfaceIndex);
        socket.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)UnicastInterface, ordered);
    }

    private static int IPAddressNetworkOrder(uint interfaceIndex) =>
        System.Net.IPAddress.HostToNetworkOrder(unchecked((int)interfaceIndex));

    private static bool IsVpn(string name, string description, int ifType)
    {
        var text = name + " " + description;
        if (Noise.Any(hint => text.Contains(hint, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        var strong = StrongVpn.Any(hint => text.Contains(hint, StringComparison.OrdinalIgnoreCase));
        if (ifType == TunnelType || strong)
        {
            return true;
        }

        // "forti" en la descripción de un Wi-Fi físico no es una VPN.
        if (LooksLikePhysicalNic(text))
        {
            return false;
        }

        return VpnHints.Any(hint => text.Contains(hint, StringComparison.OrdinalIgnoreCase));
    }

    private static bool LooksLikePhysicalNic(string text) =>
        text.Contains("wi-fi", StringComparison.OrdinalIgnoreCase)
        || text.Contains("wifi", StringComparison.OrdinalIgnoreCase)
        || text.Contains("wireless", StringComparison.OrdinalIgnoreCase)
        || text.Contains("wlan", StringComparison.OrdinalIgnoreCase)
        || text.Contains("ethernet", StringComparison.OrdinalIgnoreCase);

    private static List<AdapterRow> Read()
    {
        var found = new List<AdapterRow>();
        var size = 16 * 1024u;
        var buffer = Marshal.AllocHGlobal((int)size);
        try
        {
            var result = GetAdaptersAddresses(AddressFamilyInet, SkipNoise, IntPtr.Zero, buffer, ref size);
            if (result == BufferOverflow)
            {
                Marshal.FreeHGlobal(buffer);
                buffer = Marshal.AllocHGlobal((int)size);
                result = GetAdaptersAddresses(AddressFamilyInet, SkipNoise, IntPtr.Zero, buffer, ref size);
            }

            if (result != 0)
            {
                return found;
            }

            var cursor = buffer;
            while (cursor != IntPtr.Zero)
            {
                var ifType = Marshal.ReadInt32(cursor, IfTypeOffset);
                var description = ReadString(cursor, DescriptionOffset);
                var name = ReadString(cursor, FriendlyNameOffset);
                if (name.Length == 0)
                {
                    name = description;
                }

                var index = unchecked((uint)Marshal.ReadInt32(cursor, 4));
                var up = Marshal.ReadInt32(cursor, OperStatusOffset) == 1;
                if (ifType != LoopbackType && index != 0 && name.Length > 0)
                {
                    found.Add(new AdapterRow(name, description, index, up, ifType));
                }

                cursor = Marshal.ReadIntPtr(cursor, 8);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return found;
    }

    private static string ReadString(IntPtr cursor, int offset)
    {
        var pointer = Marshal.ReadIntPtr(cursor, offset);
        return pointer == IntPtr.Zero ? "" : Marshal.PtrToStringUni(pointer) ?? "";
    }

    private readonly record struct AdapterRow(string Name, string Description, uint Index, bool Up, int IfType);

    [DllImport("iphlpapi.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetAdaptersAddresses(uint family, uint flags, IntPtr reserved, IntPtr adapterAddresses, ref uint sizePointer);
}
