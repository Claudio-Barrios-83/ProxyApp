using System.Net;
using ProxyApp.Abstractions.Configuration;
using ProxyApp.Abstractions.Routing;

namespace ProxyApp.Configuration.Tests;

/// <summary>Fábricas compartidas para no repetir el armado de documentos en cada test.</summary>
internal static class TestProfiles
{
    public static readonly Guid Socks5NodeId = Guid.Parse("b3a9c61d-5f42-4e8b-9a77-1c0e8d4f2a55");
    public static readonly Guid AdapterNodeId = Guid.Parse("0f1b7d2e-8c4a-4a1e-9f3b-6d5c2a7e4b10");
    public static readonly Guid BlockNodeId = Guid.Parse("d4f83a55-6e17-4c92-b0a8-2d7e5f9c8b31");

    public static OutboundNode Socks5Node(Guid? upstream = null) => new()
    {
        Id = Socks5NodeId,
        Name = "OCI Frankfurt",
        Kind = OutboundKind.Socks5,
        Host = "127.0.0.1",
        Port = 1080,
        UpstreamNodeId = upstream,
    };

    public static OutboundNode AdapterNode() => new()
    {
        Id = AdapterNodeId,
        Name = "WireGuard corporativo",
        Kind = OutboundKind.NetworkAdapter,
        Adapter = new AdapterBinding { InterfaceName = "wg-corp" },
    };

    public static OutboundNode BlockNode() => new()
    {
        Id = BlockNodeId,
        Name = "Bloquear",
        Kind = OutboundKind.Block,
    };

    public static AppRule Rule(
        string name,
        Guid nodeId,
        string[] processes,
        int priority = 0,
        TargetSelector? target = null,
        bool bypassPrivate = true,
        bool enabled = true,
        string? userSid = null) => new()
        {
            Id = Guid.NewGuid(),
            Name = name,
            Priority = priority,
            IsEnabled = enabled,
            Process = ProcessSelector.ForExecutables(processes),
            Target = target,
            OutboundNodeId = nodeId,
            BypassPrivateNetworks = bypassPrivate,
            WindowsUserSid = userSid,
        };

    public static ConnectionRequest Connection(
        string executable,
        string remoteAddress = "52.113.194.132",
        int remotePort = 443,
        string? remoteHost = null,
        TransportProtocol protocol = TransportProtocol.Tcp,
        string? userSid = null) => new()
        {
            ProcessId = 4242,
            ExecutablePath = executable,
            RemoteAddress = IPAddress.Parse(remoteAddress),
            RemotePort = remotePort,
            RemoteHost = remoteHost,
            Protocol = protocol,
            UserSid = userSid,
        };
}
