using System.Net;
using ProxyApp.Abstractions.Configuration;
using Xunit;
using ProxyApp.Abstractions.Routing;
using ProxyApp.Core.Interception;
using ProxyApp.Core.Rules;

namespace ProxyApp.Configuration.Tests;

public sealed class PacketPipelineTests
{
    private static readonly IPEndPoint Redirect = new(IPAddress.Parse("127.0.0.1"), 54321);
    private static readonly IPEndPoint UdpRelay = new(IPAddress.Parse("127.0.0.1"), 54322);
    private const int AppPid = 4242;
    private const int EnginePid = 7;

    [Fact]
    public void SynDeTeams_SeRedirigeAlListener_NoAlProxyConfigurado()
    {
        var pipeline = Pipeline();
        var syn = Packet("10.0.0.5", 40000, "52.113.194.132", 443, flags: 0x02);

        var plan = pipeline.Decide(Parse(syn), () => AppPid, Identity);

        Assert.Equal(PacketFate.ReinjectModified, plan.Fate);
        Assert.Equal(IPAddress.Loopback, plan.NewDestination);
        Assert.Equal(Redirect.Port, plan.NewDestinationPort);
        Assert.Null(plan.NewSource);
        Assert.False(plan.InjectInbound);
        Assert.True(plan.MarkLoopback);
        Assert.NotEqual(1080, plan.NewDestinationPort);

        Assert.True(pipeline.Flows.TryGet(TransportProtocol.Tcp, IPAddress.Parse("10.0.0.5"), 40000, out var flow));
        Assert.EndsWith("teams.exe", flow.ExecutablePath, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(443, flow.OriginalDestination.Port);
        Assert.Equal(OutboundKind.Socks5, flow.Decision.Node!.Kind);
        Assert.Equal("10.8.0.1", flow.Decision.Node.Host);
    }

    [Fact]
    public void SynDeTeams_PorVpn_TambienSeDesviaAlListener()
    {
        var adapter = TestProfiles.AdapterNode();
        var engine = new RoutingRuleEngine(new ConfigurationDocument
        {
            Nodes = [adapter],
            Rules = [TestProfiles.Rule("Teams por WireGuard", TestProfiles.AdapterNodeId, ["teams.exe"])],
        });
        var pipeline = Pipeline(engine);
        var plan = pipeline.Decide(Parse(Packet("10.0.0.5", 40000, "52.113.194.132", 443, 0x02)), () => AppPid, Identity);

        Assert.Equal(PacketFate.ReinjectModified, plan.Fate);
        Assert.Equal(Redirect.Port, plan.NewDestinationPort);
        Assert.Equal(OutboundKind.NetworkAdapter, pipeline.Flows.TryGet(TransportProtocol.Tcp, IPAddress.Parse("10.0.0.5"), 40000, out var flow) ? flow.Decision.Node!.Kind : OutboundKind.Direct);
    }

    [Fact]
    public void SynAckDelListener_RestauraElServidorOriginal_YEntraPorElLadoInbound()
    {
        var pipeline = Pipeline();
        pipeline.Decide(Parse(Packet("10.0.0.5", 40000, "52.113.194.132", 443, 0x02)), () => AppPid, Identity);

        // El listener contesta desde su puerto. Flags SYN+ACK (0x12).
        var synAck = Parse(Packet("127.0.0.1", Redirect.Port, "10.0.0.5", 40000, 0x12));
        var plan = pipeline.Decide(synAck, () => null, _ => null);

        Assert.Equal(PacketFate.ReinjectModified, plan.Fate);
        Assert.Equal(IPAddress.Parse("52.113.194.132"), plan.NewSource);
        Assert.Equal(443, plan.NewSourcePort);
        Assert.Null(plan.NewDestination);
        Assert.True(plan.InjectInbound);
        Assert.False(plan.MarkLoopback);
    }

    [Fact]
    public void AckPosterior_ReutilizaLaEntrada_AunqueLaReglaYaNoExista()
    {
        var engine = Engine();
        var pipeline = Pipeline(engine);
        pipeline.Decide(Parse(Packet("10.0.0.5", 40000, "52.113.194.132", 443, 0x02)), () => AppPid, Identity);
        engine.Publish(ConfigurationDocument.Empty);

        var ack = Parse(Packet("10.0.0.5", 40000, "52.113.194.132", 443, 0x10));
        var plan = pipeline.Decide(ack, () => null, _ => null);

        Assert.Equal(PacketFate.ReinjectModified, plan.Fate);
        Assert.Equal(Redirect.Port, plan.NewDestinationPort);
    }

    [Fact]
    public void ProcesoAjeno_SaleSinTraducir()
    {
        var pipeline = Pipeline();
        var plan = pipeline.Decide(
            Parse(Packet("10.0.0.5", 41000, "1.1.1.1", 443, 0x02)),
            () => 99,
            _ => new ProcessIdentity(@"C:\Windows\System32\notepad.exe", null));

        Assert.Equal(PacketFate.ReinjectUnchanged, plan.Fate);
        Assert.Equal(0, pipeline.ActiveCount());
    }

    [Fact]
    public void PidDelPropioMotor_NoSeTraduce_AunqueElNombreCasara()
    {
        var pipeline = Pipeline();
        var plan = pipeline.Decide(
            Parse(Packet("10.0.0.5", 41000, "52.113.194.132", 443, 0x02)),
            () => EnginePid,
            Identity);

        Assert.Equal(PacketFate.ReinjectUnchanged, plan.Fate);
        Assert.Equal(0, pipeline.ActiveCount());
    }

    [Fact]
    public void DestinoDelPropioProxy_PasaDeLargo()
    {
        var pipeline = Pipeline(passthrough: [new IPEndPoint(IPAddress.Parse("10.8.0.1"), 1080)]);
        var plan = pipeline.Decide(
            Parse(Packet("10.0.0.5", 42000, "10.8.0.1", 1080, 0x02)),
            () => AppPid,
            Identity);

        Assert.Equal(PacketFate.ReinjectUnchanged, plan.Fate);
    }

    [Fact]
    public void ReglaDeBloqueo_NoSeReinyecta()
    {
        var engine = new RoutingRuleEngine(new ConfigurationDocument
        {
            Nodes = [TestProfiles.BlockNode()],
            Rules = [TestProfiles.Rule("Cortar", TestProfiles.BlockNodeId, ["teams.exe"], bypassPrivate: false)],
        });
        var pipeline = Pipeline(engine);

        var plan = pipeline.Decide(Parse(Packet("10.0.0.5", 40000, "1.1.1.1", 443, 0x02)), () => AppPid, Identity);

        Assert.Equal(PacketFate.Drop, plan.Fate);
    }

    [Fact]
    public void SinPid_ElPrimerSynSeRetiene_YUnAckSueltoPasa()
    {
        var pipeline = Pipeline();

        Assert.Equal(PacketFate.Hold, pipeline.Decide(Parse(Packet("10.0.0.5", 40000, "1.1.1.1", 443, 0x02)), () => null, Identity).Fate);
        Assert.Equal(PacketFate.ReinjectUnchanged, pipeline.Decide(Parse(Packet("10.0.0.5", 40000, "1.1.1.1", 443, 0x10)), () => null, Identity).Fate);
    }

    [Fact]
    public void TcpSinFlujoYSinSyn_NoConsultaLaTablaDeConexiones()
    {
        var pipeline = Pipeline();
        var consultas = 0;

        var plan = pipeline.Decide(
            Parse(Packet("10.0.0.5", 40000, "1.1.1.1", 443, 0x10)),
            () => { consultas++; return AppPid; },
            Identity);

        Assert.Equal(PacketFate.ReinjectUnchanged, plan.Fate);
        Assert.Equal(0, consultas);
    }

    [Fact]
    public void UdpSinPid_SaleSinRetener_ParaNoRomperWireGuard()
    {
        var pipeline = Pipeline();
        var wireguard = Parse(Udp("10.0.0.5", 51820, "193.0.0.1", 51820));

        Assert.Equal(PacketFate.ReinjectUnchanged, pipeline.Decide(wireguard, () => null, Identity).Fate);
        Assert.Equal(0, pipeline.ActiveCount());
    }

    [Fact]
    public void UdpDeProcesoAjeno_SaleSinTraducir()
    {
        var pipeline = Pipeline();
        var plan = pipeline.Decide(
            Parse(Udp("10.0.0.5", 51820, "193.0.0.1", 51820)),
            () => 99,
            _ => new ProcessIdentity(@"C:\Program Files\Proton\ProtonVPN.Service.exe", null));

        Assert.Equal(PacketFate.ReinjectUnchanged, plan.Fate);
        Assert.Equal(0, pipeline.ActiveCount());
    }

    [Fact]
    public void MapaDeSockets_DesbloqueaElSynRetenido()
    {
        var map = new SocketProcessMap();
        var pipeline = Pipeline();
        var syn = Parse(Packet("10.0.0.5", 40000, "52.113.194.132", 443, 0x02));

        int? Resolve() => map.TryGet(TransportProtocol.Tcp, syn.Source, syn.SourcePort, syn.Destination, syn.DestinationPort, out var pid)
            ? pid
            : null;

        Assert.Equal(PacketFate.Hold, pipeline.Decide(syn, Resolve, Identity).Fate);

        map.Connected(TransportProtocol.Tcp, syn.Source, syn.SourcePort, syn.Destination, syn.DestinationPort, AppPid);

        Assert.Equal(PacketFate.ReinjectModified, pipeline.Decide(syn, Resolve, Identity).Fate);
    }

    [Fact]
    public void Quic_SeDescarta_ParaForzarElFallbackTcp()
    {
        var pipeline = Pipeline();
        var quic = Parse(Udp("10.0.0.5", 50000, "52.113.194.132", 443));

        Assert.Equal(PacketFate.Drop, pipeline.Decide(quic, () => AppPid, Identity).Fate);
    }

    [Fact]
    public void UdpConRelay_SeTraduceAlPuertoDelRelay()
    {
        var proxy = TestProfiles.Socks5Node() with
        {
            Host = "10.8.0.1",
            Port = 1080,
            SupportsUdpAssociate = true,
        };
        var engine = new RoutingRuleEngine(new ConfigurationDocument
        {
            Nodes = [proxy],
            Rules = [TestProfiles.Rule("Media", TestProfiles.Socks5NodeId, ["teams.exe"])],
        });
        var pipeline = Pipeline(engine, udpRelay: UdpRelay, blockQuic: false);
        var datagram = Parse(Udp("10.0.0.5", 50000, "52.113.194.132", 3478));

        var plan = pipeline.Decide(datagram, () => AppPid, Identity);

        Assert.Equal(PacketFate.ReinjectModified, plan.Fate);
        Assert.Equal(UdpRelay.Port, plan.NewDestinationPort);
    }

    [Fact]
    public void ReescrituraMasChecksum_VerificaCabeceraYSegmento()
    {
        var packet = Packet("10.0.0.5", 40000, "52.113.194.132", 443, 0x02, payload: new byte[] { 0x16, 0x03, 0x01 });
        InternetChecksum.Apply(packet);
        Assert.True(ChecksumHolds(packet.AsSpan(0, 20)));

        Ipv4Packet.RewriteEndpoints(packet, null, null, IPAddress.Loopback, Redirect.Port);
        Assert.False(ChecksumHolds(packet.AsSpan(0, 20)));

        InternetChecksum.Apply(packet);
        var parsed = Parse(packet);
        Assert.Equal(IPAddress.Loopback, parsed.Destination);
        Assert.Equal(Redirect.Port, parsed.DestinationPort);
        Assert.Equal(IPAddress.Parse("10.0.0.5"), parsed.Source);
        Assert.True(parsed.IsInitialSyn);
        Assert.True(ChecksumHolds(packet.AsSpan(0, parsed.HeaderLength)));
        Assert.True(TransportChecksumHolds(packet, parsed));
    }

    [Fact]
    public void ChecksumDeCabeceraIpv4_CoincideConElVectorConocido()
    {
        byte[] header =
        [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
            0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
            0xc0, 0xa8, 0x00, 0xc7,
        ];

        Assert.Equal(0xB861, InternetChecksum.OnesComplement(header));
    }

    private static PacketPipeline Pipeline(
        RoutingRuleEngine? engine = null,
        IPEndPoint? udpRelay = null,
        bool blockQuic = true,
        IReadOnlyList<IPEndPoint>? passthrough = null) =>
        new(
            engine ?? Engine(),
            Redirect,
            EnginePid,
            blockQuic,
            udpRelay,
            passthrough is null ? null : () => passthrough);

    private static RoutingRuleEngine Engine()
    {
        var proxy = TestProfiles.Socks5Node() with { Host = "10.8.0.1", Port = 1080 };
        return new RoutingRuleEngine(new ConfigurationDocument
        {
            Nodes = [proxy],
            Rules = [TestProfiles.Rule("Colaboración", TestProfiles.Socks5NodeId, ["teams.exe"])],
        });
    }

    private static ProcessIdentity? Identity(int processId) =>
        new(@"C:\Program Files\WindowsApps\MSTeams\teams.exe", "S-1-5-21-1-2-3-1001");

    private static ParsedIpv4Packet Parse(byte[] packet)
    {
        Assert.True(Ipv4Packet.TryParse(packet, out var parsed));
        return parsed;
    }

    private static byte[] Packet(string source, int sourcePort, string destination, int destinationPort, byte flags, byte[]? payload = null)
    {
        payload ??= [];
        var bytes = new byte[40 + payload.Length];
        bytes[0] = 0x45;
        bytes[2] = (byte)(bytes.Length >> 8);
        bytes[3] = (byte)bytes.Length;
        bytes[8] = 64;
        bytes[9] = 6;
        IPAddress.Parse(source).TryWriteBytes(bytes.AsSpan(12, 4), out _);
        IPAddress.Parse(destination).TryWriteBytes(bytes.AsSpan(16, 4), out _);
        WritePort(bytes, 20, sourcePort);
        WritePort(bytes, 22, destinationPort);
        bytes[32] = 0x50;
        bytes[33] = flags;
        payload.CopyTo(bytes.AsSpan(40));
        return bytes;
    }

    private static byte[] Udp(string source, int sourcePort, string destination, int destinationPort)
    {
        var bytes = new byte[28];
        bytes[0] = 0x45;
        bytes[2] = 0;
        bytes[3] = 28;
        bytes[8] = 64;
        bytes[9] = 17;
        IPAddress.Parse(source).TryWriteBytes(bytes.AsSpan(12, 4), out _);
        IPAddress.Parse(destination).TryWriteBytes(bytes.AsSpan(16, 4), out _);
        WritePort(bytes, 20, sourcePort);
        WritePort(bytes, 22, destinationPort);
        bytes[24] = 0;
        bytes[25] = 8;
        return bytes;
    }

    private static void WritePort(byte[] packet, int offset, int port)
    {
        packet[offset] = (byte)(port >> 8);
        packet[offset + 1] = (byte)port;
    }

    private static bool ChecksumHolds(ReadOnlySpan<byte> data)
    {
        uint sum = 0;
        var index = 0;
        for (; index + 1 < data.Length; index += 2)
        {
            sum += (uint)((data[index] << 8) | data[index + 1]);
        }

        if (index < data.Length)
        {
            sum += (uint)(data[index] << 8);
        }

        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return sum == 0xFFFF;
    }

    private static bool TransportChecksumHolds(byte[] packet, ParsedIpv4Packet parsed)
    {
        var segmentLength = parsed.TotalLength - parsed.HeaderLength;
        var pseudo = new byte[12 + segmentLength];
        packet.AsSpan(12, 8).CopyTo(pseudo);
        pseudo[9] = packet[9];
        pseudo[10] = (byte)(segmentLength >> 8);
        pseudo[11] = (byte)segmentLength;
        packet.AsSpan(parsed.HeaderLength, segmentLength).CopyTo(pseudo.AsSpan(12));
        return ChecksumHolds(pseudo);
    }
}

internal static class PipelineCount
{
    public static int ActiveCount(this PacketPipeline pipeline) => pipeline.Flows.Count;
}
