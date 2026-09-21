using System.Text.Json;
using System.Text.Json.Serialization;
using ProxyApp.Abstractions.Configuration;

namespace ProxyApp.Persistence.Json;

/// <summary>
/// Serializa <see cref="PortRange"/> como <c>"443"</c> o <c>"8000-8100"</c> en vez
/// de como objeto, para que el JSON sea cómodo de editar a mano.
/// </summary>
public sealed class PortRangeJsonConverter : JsonConverter<PortRange>
{
    public override PortRange Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Number)
        {
            return PortRange.Single(reader.GetInt32());
        }

        var raw = reader.GetString();
        if (string.IsNullOrWhiteSpace(raw))
        {
            throw new JsonException("Rango de puertos vacío.");
        }

        try
        {
            return PortRange.Parse(raw);
        }
        catch (Exception ex) when (ex is FormatException or OverflowException or ArgumentException)
        {
            throw new JsonException($"Rango de puertos no válido: '{raw}'.", ex);
        }
    }

    public override void Write(Utf8JsonWriter writer, PortRange value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteStringValue(value.ToString());
    }
}
