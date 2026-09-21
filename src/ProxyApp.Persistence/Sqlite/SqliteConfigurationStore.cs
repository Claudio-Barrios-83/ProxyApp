using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using ProxyApp.Abstractions.Configuration;
using ProxyApp.Persistence.Json;

namespace ProxyApp.Persistence.Sqlite;

/// <summary>
/// Persistencia en SQLite. Frente al store JSON aporta escritura transaccional y
/// acceso concurrente seguro desde el servicio y la UI a la vez.
/// </summary>
/// <remarks>
/// El esquema es deliberadamente plano: las columnas que el usuario filtra o
/// ordena en la UI son columnas reales, y lo que solo se lee entero (selectores,
/// binding de adaptador) va como JSON en una columna de texto. Evita un ORM y
/// mantiene la migración de esquema bajo control.
/// </remarks>
public sealed class SqliteConfigurationStore : IConfigurationStore, IDisposable
{
    private readonly string _connectionString;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private bool _disposed;

    public SqliteConfigurationStore(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);

        var fullPath = Path.GetFullPath(databasePath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);

        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = fullPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true,
        }.ToString();
    }

    public event EventHandler<ConfigurationChangedEventArgs>? Changed;

    /// <summary>Crea el esquema si no existe. Idempotente.</summary>
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        await ExecuteAsync(
            connection,
            """
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS outbound_nodes (
                id                          TEXT    NOT NULL PRIMARY KEY,
                name                        TEXT    NOT NULL,
                kind                        TEXT    NOT NULL,
                is_enabled                  INTEGER NOT NULL DEFAULT 1,
                host                        TEXT    NULL,
                port                        INTEGER NOT NULL DEFAULT 0,
                username                    TEXT    NULL,
                protected_password          TEXT    NULL,
                resolve_hostnames_remotely  INTEGER NOT NULL DEFAULT 1,
                supports_udp_associate      INTEGER NOT NULL DEFAULT 0,
                adapter_json                TEXT    NULL,
                upstream_node_id            TEXT    NULL REFERENCES outbound_nodes(id) ON DELETE SET NULL,
                connect_timeout_seconds     REAL    NOT NULL DEFAULT 10
            );

            CREATE TABLE IF NOT EXISTS app_rules (
                id                       TEXT    NOT NULL PRIMARY KEY,
                name                     TEXT    NOT NULL,
                priority                 INTEGER NOT NULL DEFAULT 0,
                is_enabled               INTEGER NOT NULL DEFAULT 1,
                process_json             TEXT    NOT NULL,
                target_json              TEXT    NULL,
                outbound_node_id         TEXT    NOT NULL REFERENCES outbound_nodes(id) ON DELETE CASCADE,
                bypass_private_networks  INTEGER NOT NULL DEFAULT 1,
                windows_user_sid         TEXT    NULL
            );

            CREATE INDEX IF NOT EXISTS ix_app_rules_priority ON app_rules(is_enabled, priority);

            CREATE TABLE IF NOT EXISTS engine_settings (
                id           INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
                payload_json TEXT    NOT NULL
            );
            """,
            cancellationToken).ConfigureAwait(false);

        await using var check = connection.CreateCommand();
        check.CommandText = "SELECT COUNT(*) FROM schema_version;";
        var rows = Convert.ToInt64(await check.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture);

        if (rows == 0)
        {
            await using var seed = connection.CreateCommand();
            seed.CommandText = "INSERT INTO schema_version (version) VALUES ($v);";
            seed.Parameters.AddWithValue("$v", ConfigurationDocument.CurrentSchemaVersion);
            await seed.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public async ValueTask<ConfigurationDocument> LoadAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

            var nodes = await ReadNodesAsync(connection, cancellationToken).ConfigureAwait(false);
            var rules = await ReadRulesAsync(connection, cancellationToken).ConfigureAwait(false);
            var settings = await ReadSettingsAsync(connection, cancellationToken).ConfigureAwait(false);

            return new ConfigurationDocument
            {
                SchemaVersion = ConfigurationDocument.CurrentSchemaVersion,
                Nodes = nodes,
                Rules = rules,
                Settings = settings,
            };
        }
        catch (SqliteException ex)
        {
            throw new ConfigurationStoreException("No se pudo leer la base de configuración.", ex);
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
            await using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

            // Reemplazo completo dentro de una transacción: el motor nunca puede
            // observar un estado con reglas nuevas y nodos viejos.
            await ExecuteAsync(connection, "DELETE FROM app_rules; DELETE FROM outbound_nodes;", cancellationToken)
                .ConfigureAwait(false);

            // Los nodos sin upstream van primero para no violar la clave foránea
            // de las cadenas de salida.
            foreach (var node in document.Nodes.OrderBy(n => n.UpstreamNodeId is null ? 0 : 1))
            {
                await InsertNodeAsync(connection, node, cancellationToken).ConfigureAwait(false);
            }

            foreach (var rule in document.Rules)
            {
                await InsertRuleAsync(connection, rule, cancellationToken).ConfigureAwait(false);
            }

            await using (var settings = connection.CreateCommand())
            {
                settings.CommandText =
                    "INSERT INTO engine_settings (id, payload_json) VALUES (1, $p) " +
                    "ON CONFLICT(id) DO UPDATE SET payload_json = excluded.payload_json;";
                settings.Parameters.AddWithValue("$p", JsonSerializer.Serialize(document.Settings, ConfigurationJson.Options));
                await settings.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (SqliteException ex)
        {
            throw new ConfigurationStoreException("No se pudo guardar la configuración.", ex);
        }
        finally
        {
            _gate.Release();
        }

        Changed?.Invoke(this, new ConfigurationChangedEventArgs(document));
    }

    private static async Task<List<OutboundNode>> ReadNodesAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        var nodes = new List<OutboundNode>();

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM outbound_nodes;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var username = reader["username"] as string;
            var password = reader["protected_password"] as string;

            nodes.Add(new OutboundNode
            {
                Id = Guid.Parse((string)reader["id"]),
                Name = (string)reader["name"],
                Kind = Enum.Parse<OutboundKind>((string)reader["kind"], ignoreCase: true),
                IsEnabled = Convert.ToInt64(reader["is_enabled"], CultureInfo.InvariantCulture) != 0,
                Host = reader["host"] as string,
                Port = Convert.ToInt32(reader["port"], CultureInfo.InvariantCulture),
                Credentials = username is null || password is null
                    ? null
                    : new ProxyCredentials { Username = username, ProtectedPassword = password },
                ResolveHostnamesRemotely = Convert.ToInt64(reader["resolve_hostnames_remotely"], CultureInfo.InvariantCulture) != 0,
                SupportsUdpAssociate = Convert.ToInt64(reader["supports_udp_associate"], CultureInfo.InvariantCulture) != 0,
                Adapter = reader["adapter_json"] is string adapterJson
                    ? JsonSerializer.Deserialize<AdapterBinding>(adapterJson, ConfigurationJson.Options)
                    : null,
                UpstreamNodeId = reader["upstream_node_id"] is string upstream ? Guid.Parse(upstream) : null,
                ConnectTimeout = TimeSpan.FromSeconds(Convert.ToDouble(reader["connect_timeout_seconds"], CultureInfo.InvariantCulture)),
            });
        }

        return nodes;
    }

    private static async Task<List<AppRule>> ReadRulesAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        var rules = new List<AppRule>();

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM app_rules ORDER BY priority, name;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            rules.Add(new AppRule
            {
                Id = Guid.Parse((string)reader["id"]),
                Name = (string)reader["name"],
                Priority = Convert.ToInt32(reader["priority"], CultureInfo.InvariantCulture),
                IsEnabled = Convert.ToInt64(reader["is_enabled"], CultureInfo.InvariantCulture) != 0,
                Process = JsonSerializer.Deserialize<ProcessSelector>((string)reader["process_json"], ConfigurationJson.Options)
                          ?? new ProcessSelector(),
                Target = reader["target_json"] is string targetJson
                    ? JsonSerializer.Deserialize<TargetSelector>(targetJson, ConfigurationJson.Options)
                    : null,
                OutboundNodeId = Guid.Parse((string)reader["outbound_node_id"]),
                BypassPrivateNetworks = Convert.ToInt64(reader["bypass_private_networks"], CultureInfo.InvariantCulture) != 0,
                WindowsUserSid = reader["windows_user_sid"] as string,
            });
        }

        return rules;
    }

    private static async Task<EngineSettings> ReadSettingsAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT payload_json FROM engine_settings WHERE id = 1;";
        var payload = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string;

        return payload is null
            ? new EngineSettings()
            : JsonSerializer.Deserialize<EngineSettings>(payload, ConfigurationJson.Options) ?? new EngineSettings();
    }

    private static async Task InsertNodeAsync(SqliteConnection connection, OutboundNode node, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText =
            """
            INSERT INTO outbound_nodes
                (id, name, kind, is_enabled, host, port, username, protected_password,
                 resolve_hostnames_remotely, supports_udp_associate, adapter_json,
                 upstream_node_id, connect_timeout_seconds)
            VALUES
                ($id, $name, $kind, $enabled, $host, $port, $user, $password,
                 $resolveRemote, $udp, $adapter, $upstream, $timeout);
            """;

        command.Parameters.AddWithValue("$id", node.Id.ToString());
        command.Parameters.AddWithValue("$name", node.Name);
        command.Parameters.AddWithValue("$kind", node.Kind.ToString());
        command.Parameters.AddWithValue("$enabled", node.IsEnabled ? 1 : 0);
        command.Parameters.AddWithValue("$host", (object?)node.Host ?? DBNull.Value);
        command.Parameters.AddWithValue("$port", node.Port);
        command.Parameters.AddWithValue("$user", (object?)node.Credentials?.Username ?? DBNull.Value);
        command.Parameters.AddWithValue("$password", (object?)node.Credentials?.ProtectedPassword ?? DBNull.Value);
        command.Parameters.AddWithValue("$resolveRemote", node.ResolveHostnamesRemotely ? 1 : 0);
        command.Parameters.AddWithValue("$udp", node.SupportsUdpAssociate ? 1 : 0);
        command.Parameters.AddWithValue(
            "$adapter",
            node.Adapter is null ? DBNull.Value : JsonSerializer.Serialize(node.Adapter, ConfigurationJson.Options));
        command.Parameters.AddWithValue("$upstream", (object?)node.UpstreamNodeId?.ToString() ?? DBNull.Value);
        command.Parameters.AddWithValue("$timeout", node.ConnectTimeout.TotalSeconds);

        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task InsertRuleAsync(SqliteConnection connection, AppRule rule, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText =
            """
            INSERT INTO app_rules
                (id, name, priority, is_enabled, process_json, target_json,
                 outbound_node_id, bypass_private_networks, windows_user_sid)
            VALUES
                ($id, $name, $priority, $enabled, $process, $target,
                 $node, $bypass, $sid);
            """;

        command.Parameters.AddWithValue("$id", rule.Id.ToString());
        command.Parameters.AddWithValue("$name", rule.Name);
        command.Parameters.AddWithValue("$priority", rule.Priority);
        command.Parameters.AddWithValue("$enabled", rule.IsEnabled ? 1 : 0);
        command.Parameters.AddWithValue("$process", JsonSerializer.Serialize(rule.Process, ConfigurationJson.Options));
        command.Parameters.AddWithValue(
            "$target",
            rule.Target is null ? DBNull.Value : JsonSerializer.Serialize(rule.Target, ConfigurationJson.Options));
        command.Parameters.AddWithValue("$node", rule.OutboundNodeId.ToString());
        command.Parameters.AddWithValue("$bypass", rule.BypassPrivateNetworks ? 1 : 0);
        command.Parameters.AddWithValue("$sid", (object?)rule.WindowsUserSid ?? DBNull.Value);

        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task ExecuteAsync(SqliteConnection connection, string sql, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _gate.Dispose();

        // El pool mantiene el fichero abierto; sin esto los tests no pueden
        // borrar la base temporal en Windows.
        SqliteConnection.ClearPool(new SqliteConnection(_connectionString));
    }
}
