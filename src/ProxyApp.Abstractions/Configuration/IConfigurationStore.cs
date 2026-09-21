namespace ProxyApp.Abstractions.Configuration;

/// <summary>
/// Persistencia de la configuración. Hay dos implementaciones intercambiables
/// (JSON y SQLite) para que el usuario pueda versionar el perfil en un fichero
/// o dejarlo en una base local sin que el motor se entere.
/// </summary>
public interface IConfigurationStore
{
    /// <summary>Carga el documento. Devuelve <see cref="ConfigurationDocument.Empty"/> si aún no existe.</summary>
    ValueTask<ConfigurationDocument> LoadAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Persiste el documento de forma atómica. Debe rechazar documentos que no
    /// pasen <see cref="ConfigurationDocument.Validate"/>.
    /// </summary>
    ValueTask SaveAsync(ConfigurationDocument document, CancellationToken cancellationToken = default);

    /// <summary>
    /// Se dispara cuando la configuración cambia por fuera del proceso (edición
    /// manual del JSON, otra instancia de la UI). Permite recarga en caliente sin
    /// reiniciar el motor.
    /// </summary>
    event EventHandler<ConfigurationChangedEventArgs>? Changed;
}

public sealed class ConfigurationChangedEventArgs(ConfigurationDocument document) : EventArgs
{
    public ConfigurationDocument Document { get; } = document;
}

/// <summary>Error de persistencia o de validación al guardar.</summary>
public sealed class ConfigurationStoreException : Exception
{
    public ConfigurationStoreException(string message)
        : base(message)
    {
    }

    public ConfigurationStoreException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public ConfigurationStoreException(string message, IReadOnlyList<string> validationErrors)
        : base(message + Environment.NewLine + string.Join(Environment.NewLine, validationErrors))
    {
        ValidationErrors = validationErrors;
    }

    public IReadOnlyList<string> ValidationErrors { get; } = [];
}
