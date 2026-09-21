using System.Text.Json;
using System.Text.Json.Serialization;

namespace ProxyApp.Persistence.Json;

/// <summary>
/// Opciones de serialización compartidas por el store de fichero, el export de
/// la UI y el contrato IPC, para que un perfil exportado se pueda reimportar tal cual.
/// </summary>
public static class ConfigurationJson
{
    public static JsonSerializerOptions Options { get; } = Create();

    private static JsonSerializerOptions Create()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
        };

        // Los enums se guardan como texto: el fichero es editable a mano y un
        // cambio de orden en el enum no debe reinterpretar configuraciones viejas.
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
        options.Converters.Add(new PortRangeJsonConverter());

        return options;
    }
}
