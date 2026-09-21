using System.Text.Json;
using ProxyApp.Abstractions.Configuration;

namespace ProxyApp.Persistence.Json;

/// <summary>
/// Persistencia en un único fichero JSON, con escritura atómica y recarga en
/// caliente cuando alguien lo edita por fuera.
/// </summary>
/// <remarks>
/// Es el store por defecto: el perfil queda en texto plano versionable y es
/// trivial compartirlo entre equipos. Para catálogos grandes de reglas o
/// escritura concurrente desde varios procesos conviene el store SQLite.
/// </remarks>
public sealed class JsonConfigurationStore : IConfigurationStore, IDisposable
{
    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly FileSystemWatcher? _watcher;
    private readonly System.Timers.Timer? _debounce;
    private bool _disposed;

    /// <param name="path">Ruta del fichero, típicamente <c>%ProgramData%\ProxyApp\config.json</c>.</param>
    /// <param name="watchForChanges">Activa la recarga en caliente.</param>
    public JsonConfigurationStore(string path, bool watchForChanges = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);

        var directory = Path.GetDirectoryName(_path)!;
        Directory.CreateDirectory(directory);

        if (!watchForChanges)
        {
            return;
        }

        // Los editores escriben en varios pasos (temporal + rename), así que un
        // único cambio genera varios eventos. El debounce evita recargar a medias.
        _debounce = new System.Timers.Timer(400) { AutoReset = false };
        _debounce.Elapsed += async (_, _) => await RaiseChangedAsync().ConfigureAwait(false);

        _watcher = new FileSystemWatcher(directory, Path.GetFileName(_path))
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size,
            EnableRaisingEvents = true,
        };
        _watcher.Changed += OnFileTouched;
        _watcher.Created += OnFileTouched;
        _watcher.Renamed += OnFileTouched;
    }

    public event EventHandler<ConfigurationChangedEventArgs>? Changed;

    public async ValueTask<ConfigurationDocument> LoadAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(_path))
            {
                return ConfigurationDocument.Empty;
            }

            await using var stream = new FileStream(
                _path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 4096,
                useAsync: true);

            var document = await JsonSerializer
                .DeserializeAsync<ConfigurationDocument>(stream, ConfigurationJson.Options, cancellationToken)
                .ConfigureAwait(false);

            return document ?? ConfigurationDocument.Empty;
        }
        catch (JsonException ex)
        {
            throw new ConfigurationStoreException($"El fichero '{_path}' no es un perfil válido.", ex);
        }
        catch (IOException ex)
        {
            throw new ConfigurationStoreException($"No se pudo leer '{_path}'.", ex);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask SaveAsync(ConfigurationDocument document, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(document);

        var errors = document.Validate();
        if (errors.Count > 0)
        {
            throw new ConfigurationStoreException("La configuración no es válida:", errors);
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Escritura atómica: un corte de luz a mitad no puede dejar al motor
            // sin reglas, que es tanto como dejar tráfico saliendo en claro.
            var temporary = _path + ".tmp";

            await using (var stream = new FileStream(
                temporary,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4096,
                useAsync: true))
            {
                await JsonSerializer
                    .SerializeAsync(stream, document, ConfigurationJson.Options, cancellationToken)
                    .ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            File.Move(temporary, _path, overwrite: true);
        }
        catch (IOException ex)
        {
            throw new ConfigurationStoreException($"No se pudo escribir '{_path}'.", ex);
        }
        finally
        {
            _gate.Release();
        }
    }

    private void OnFileTouched(object sender, FileSystemEventArgs e)
    {
        _debounce?.Stop();
        _debounce?.Start();
    }

    private async Task RaiseChangedAsync()
    {
        var handler = Changed;
        if (handler is null)
        {
            return;
        }

        try
        {
            var document = await LoadAsync().ConfigureAwait(false);
            handler(this, new ConfigurationChangedEventArgs(document));
        }
        catch (ConfigurationStoreException)
        {
            // Un fichero a medio escribir no debe tumbar el servicio: se ignora
            // y el siguiente evento del watcher traerá la versión completa.
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _watcher?.Dispose();
        _debounce?.Dispose();
        _gate.Dispose();
    }
}
