using ProxyApp.Abstractions.Configuration;

namespace ProxyApp.Core.Interception;

/// <summary>
/// Checksum de Internet (RFC 1071): suma en complemento a uno de palabras de 16 bits.
/// </summary>
/// <remarks>
/// <para>
/// WinDivert entrega muchos paquetes salientes con el checksum a cero y la marca
/// correspondiente de <c>WINDIVERT_ADDRESS</c> apagada. Es el checksum offload de
/// la NIC: la pila deja el campo vacío porque esperaba que lo calculara el
/// hardware. En cuanto cambiamos una dirección o un puerto, aunque el checksum
/// original fuera válido, deja de serlo. Reinyectar sin recalcular hace que el
/// peer descarte el segmento en silencio y el handshake se quede en SYN_SENT.
/// </para>
/// <para>
/// El checksum TCP y el UDP no cubren solo su cabecera. Cubren una
/// pseudo-cabecera que incluye las direcciones IP, el protocolo y la longitud
/// del segmento. Cambiar el puerto obliga a recalcularlo entero; cambiar la IP
/// también, aunque el puerto no se toque. No sirve con ajustar el campo a mano.
/// </para>
/// <para>
/// En producción <c>WinDivertHelperCalcChecksums</c> vuelve a hacer este cálculo
/// y, además, enciende las marcas <c>IPChecksum</c>, <c>TCPChecksum</c> y
/// <c>UDPChecksum</c> de la dirección. Si esas marcas quedan encendidas con el
/// valor viejo, <c>WinDivertSend</c> se fía del campo y no lo toca. Esta clase
/// existe para que el algoritmo sea comprobable sin el driver.
/// </para>
/// </remarks>
public static class InternetChecksum
{
    /// <summary>
    /// Recalcula el checksum de la cabecera IPv4 y el del segmento TCP o UDP.
    /// Usa la longitud total declarada en la cabecera IP, no el tamaño del buffer.
    /// </summary>
    public static void Apply(Span<byte> packet)
    {
        if (!Ipv4Packet.TryParse(packet, out var parsed))
        {
            throw new ArgumentException("El buffer no contiene un datagrama IPv4 TCP/UDP completo.", nameof(packet));
        }

        var headerLength = parsed.HeaderLength;
        packet[10] = 0;
        packet[11] = 0;
        Write(packet, 10, OnesComplement(packet[..headerLength]));

        var segmentOffset = headerLength;
        var segmentLength = parsed.TotalLength - headerLength;
        var checksumOffset = segmentOffset + (parsed.Protocol == TransportProtocol.Tcp ? 16 : 6);
        packet[checksumOffset] = 0;
        packet[checksumOffset + 1] = 0;

        // Pseudo-cabecera IPv4 (RFC 793 §3.1): IP origen, IP destino, cero,
        // protocolo y longitud del segmento en este orden y en orden de red.
        Span<byte> pseudo = stackalloc byte[12];
        packet.Slice(12, 8).CopyTo(pseudo);
        pseudo[8] = 0;
        pseudo[9] = packet[9];
        pseudo[10] = (byte)(segmentLength >> 8);
        pseudo[11] = (byte)segmentLength;

        var sum = SumWords(pseudo) + SumWords(packet.Slice(segmentOffset, segmentLength));

        var folded = Fold(sum);

        // En UDP un resultado 0 se transmite como 0xFFFF. El 0 significa
        // "checksum desactivado" en IPv4, y un receptor lo trataría como ausencia
        // de checksum en vez de como un checksum válido.
        if (parsed.Protocol == TransportProtocol.Udp && folded == 0)
        {
            folded = 0xFFFF;
        }

        Write(packet, checksumOffset, folded);
    }

    /// <summary>Suma de comprobación del buffer. El campo de checksum debe llegar a cero.</summary>
    public static ushort OnesComplement(ReadOnlySpan<byte> data) => Fold(SumWords(data));

    private static uint SumWords(ReadOnlySpan<byte> data)
    {
        uint sum = 0;
        var index = 0;

        for (; index + 1 < data.Length; index += 2)
        {
            sum += (uint)((data[index] << 8) | data[index + 1]);
        }

        // Un byte impar se suma como palabra con el octeto bajo a cero (RFC 1071).
        if (index < data.Length)
        {
            sum += (uint)(data[index] << 8);
        }

        return sum;
    }

    private static ushort Fold(uint sum)
    {
        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (ushort)~sum;
    }

    private static void Write(Span<byte> packet, int offset, ushort value)
    {
        packet[offset] = (byte)(value >> 8);
        packet[offset + 1] = (byte)value;
    }
}
