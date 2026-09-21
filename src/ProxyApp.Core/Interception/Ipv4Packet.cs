using System.Net;
using System.Net.Sockets;
using ProxyApp.Abstractions.Configuration;

namespace ProxyApp.Core.Interception;

/// <summary>
/// Vista de un datagrama IPv4 con carga TCP o UDP. Las direcciones y los puertos
/// se leen en orden de red, que es como viajan en el cable.
/// </summary>
public readonly record struct ParsedIpv4Packet
{
    public int HeaderLength { get; init; }

    public int TotalLength { get; init; }

    public TransportProtocol Protocol { get; init; }

    public IPAddress Source { get; init; }

    public int SourcePort { get; init; }

    public IPAddress Destination { get; init; }

    public int DestinationPort { get; init; }

    /// <summary>Bit SYN de TCP. Siempre falso en UDP.</summary>
    public bool Syn { get; init; }

    /// <summary>Bit ACK de TCP. Un SYN inicial de <c>connect()</c> llega con este bit apagado.</summary>
    public bool Ack { get; init; }

    public bool Fin { get; init; }

    public bool Rst { get; init; }

    /// <summary>Primer segmento de un <c>connect()</c>: SYN sin ACK. Abre el estado en la tabla NAT.</summary>
    public bool IsInitialSyn => Protocol == TransportProtocol.Tcp && Syn && !Ack;
}

/// <summary>Lectura y reescritura de datagramas IPv4 sin depender de WinDivert.</summary>
public static class Ipv4Packet
{
    private const byte Tcp = 6;
    private const byte Udp = 17;

    public static bool TryParse(ReadOnlySpan<byte> packet, out ParsedIpv4Packet parsed)
    {
        parsed = default;

        if (packet.Length < 20 || packet[0] >> 4 != 4)
        {
            return false;
        }

        var headerLength = (packet[0] & 0x0F) * 4;
        if (headerLength < 20 || packet.Length < headerLength)
        {
            return false;
        }

        // DF (0x4000) es normal. Cualquier fragmento real se deja pasar intacto:
        // traducir solo el primer fragmento partiría el datagrama entre dos destinos.
        var fragment = (packet[6] << 8) | packet[7];
        if ((fragment & 0x1FFF) != 0 || (fragment & 0x2000) != 0)
        {
            return false;
        }

        var totalLength = (packet[2] << 8) | packet[3];
        if (totalLength < headerLength || totalLength > packet.Length)
        {
            return false;
        }

        var protocol = packet[9] switch
        {
            Tcp => TransportProtocol.Tcp,
            Udp => TransportProtocol.Udp,
            _ => (TransportProtocol?)null,
        };

        if (protocol is null)
        {
            return false;
        }

        var transportLength = totalLength - headerLength;
        var minimumTransport = protocol == TransportProtocol.Tcp ? 20 : 8;
        if (transportLength < minimumTransport)
        {
            return false;
        }

        var flags = protocol == TransportProtocol.Tcp ? packet[headerLength + 13] : (byte)0;

        parsed = new ParsedIpv4Packet
        {
            HeaderLength = headerLength,
            TotalLength = totalLength,
            Protocol = protocol.Value,
            Source = new IPAddress(packet.Slice(12, 4)),
            SourcePort = ReadPort(packet, headerLength),
            Destination = new IPAddress(packet.Slice(16, 4)),
            DestinationPort = ReadPort(packet, headerLength + 2),
            Syn = (flags & 0x02) != 0,
            Ack = (flags & 0x10) != 0,
            Fin = (flags & 0x01) != 0,
            Rst = (flags & 0x04) != 0,
        };

        return true;
    }

    /// <summary>
    /// Sustituye los extremos indicados. Un null deja ese extremo como está:
    /// la ida solo cambia el destino y la vuelta solo cambia el origen.
    /// No toca números de secuencia ni el payload.
    /// </summary>
    public static void RewriteEndpoints(
        Span<byte> packet,
        IPAddress? source,
        int? sourcePort,
        IPAddress? destination,
        int? destinationPort)
    {
        if (!TryParse(packet, out var parsed))
        {
            throw new ArgumentException("El buffer no contiene un datagrama IPv4 TCP/UDP completo.", nameof(packet));
        }

        if (source is not null)
        {
            WriteAddress(packet, 12, source);
        }

        if (destination is not null)
        {
            WriteAddress(packet, 16, destination);
        }

        if (sourcePort is not null)
        {
            WritePort(packet, parsed.HeaderLength, sourcePort.Value);
        }

        if (destinationPort is not null)
        {
            WritePort(packet, parsed.HeaderLength + 2, destinationPort.Value);
        }
    }

    private static int ReadPort(ReadOnlySpan<byte> packet, int offset) => (packet[offset] << 8) | packet[offset + 1];

    private static void WritePort(Span<byte> packet, int offset, int port)
    {
        packet[offset] = (byte)(port >> 8);
        packet[offset + 1] = (byte)port;
    }

    private static void WriteAddress(Span<byte> packet, int offset, IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new ArgumentException("La traducción del motor IPv4 solo admite direcciones IPv4.", nameof(address));
        }

        address.TryWriteBytes(packet.Slice(offset, 4), out _);
    }
}
