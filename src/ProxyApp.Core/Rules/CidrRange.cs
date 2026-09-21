using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace ProxyApp.Core.Rules;

/// <summary>
/// Rango de direcciones en notación CIDR, IPv4 e IPv6. La comparación es por
/// bytes para no depender de aritmética de 32 bits.
/// </summary>
public sealed class CidrRange
{
    private readonly byte[] _network;
    private readonly int _prefixLength;
    private readonly AddressFamily _family;

    private CidrRange(byte[] network, int prefixLength, AddressFamily family)
    {
        _network = network;
        _prefixLength = prefixLength;
        _family = family;
    }

    public static CidrRange Parse(string value)
    {
        if (!TryParse(value, out var range))
        {
            throw new FormatException($"CIDR no válido: '{value}'.");
        }

        return range;
    }

    public static bool TryParse(string? value, out CidrRange range)
    {
        range = null!;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var span = value.AsSpan().Trim();
        var slash = span.IndexOf('/');

        ReadOnlySpan<char> addressPart = slash < 0 ? span : span[..slash];
        if (!IPAddress.TryParse(addressPart, out var address))
        {
            return false;
        }

        var bits = address.GetAddressBytes().Length * 8;
        var prefixLength = bits;

        if (slash >= 0 &&
            (!int.TryParse(span[(slash + 1)..], NumberStyles.Integer, CultureInfo.InvariantCulture, out prefixLength) ||
             prefixLength < 0 ||
             prefixLength > bits))
        {
            return false;
        }

        range = new CidrRange(Mask(address.GetAddressBytes(), prefixLength), prefixLength, address.AddressFamily);
        return true;
    }

    public bool Contains(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        // Una dirección IPv4 mapeada en IPv6 debe compararse contra rangos IPv4.
        if (address.AddressFamily != _family)
        {
            if (_family == AddressFamily.InterNetwork && address.IsIPv4MappedToIPv6)
            {
                address = address.MapToIPv4();
            }
            else
            {
                return false;
            }
        }

        var masked = Mask(address.GetAddressBytes(), _prefixLength);
        return masked.AsSpan().SequenceEqual(_network);
    }

    private static byte[] Mask(byte[] address, int prefixLength)
    {
        var result = new byte[address.Length];
        var fullBytes = prefixLength / 8;
        var remainingBits = prefixLength % 8;

        Array.Copy(address, result, fullBytes);

        if (remainingBits > 0 && fullBytes < result.Length)
        {
            var mask = (byte)(0xFF << (8 - remainingBits));
            result[fullBytes] = (byte)(address[fullBytes] & mask);
        }

        return result;
    }
}
