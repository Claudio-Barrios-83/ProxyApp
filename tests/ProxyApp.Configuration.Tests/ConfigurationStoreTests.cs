using System.Text.Json;
using ProxyApp.Abstractions.Configuration;
using ProxyApp.Persistence.Json;
using ProxyApp.Persistence.Sqlite;
using Xunit;

namespace ProxyApp.Configuration.Tests;

public sealed class ConfigurationStoreTests : IDisposable
{
    private readonly string _workspace = Directory.CreateTempSubdirectory("proxyapp-tests-").FullName;

    [Fact]
    public async Task PerfilDeEjemplo_SeDeserializaYEsValido()
    {
        using var store = new JsonConfigurationStore(
            Path.Combine(AppContext.BaseDirectory, "sample-profile.json"),
            watchForChanges: false);

        var document = await store.LoadAsync();

        Assert.Empty(document.Validate());
        Assert.Equal(4, document.Nodes.Count);
        Assert.Equal(3, document.Rules.Count);

        var socks = document.Nodes.Single(n => n.Kind == OutboundKind.Socks5);
        Assert.Equal(1080, socks.Port);
        Assert.True(socks.ResolveHostnamesRemotely);
        Assert.Equal(TestProfiles.AdapterNodeId, socks.UpstreamNodeId);

        var collaboration = document.Rules.Single(r => r.Name == "Colaboración vía OCI");
        Assert.Contains("ms-teams.exe", collaboration.Process.Patterns);
        Assert.Contains(PortRange.Single(443), collaboration.Target!.Ports);
    }

    [Fact]
    public async Task Json_RoundTripPreservaElDocumento()
    {
        var path = Path.Combine(_workspace, "config.json");
        using var store = new JsonConfigurationStore(path, watchForChanges: false);
        var original = SampleDocument();

        await store.SaveAsync(original);
        var reloaded = await store.LoadAsync();

        // Los records comparan las colecciones por referencia, así que la
        // equivalencia se afirma sobre la forma serializada.
        Assert.Equal(Canonical(original), Canonical(reloaded));
    }

    [Fact]
    public async Task Json_RechazaDocumentoInvalido()
    {
        var path = Path.Combine(_workspace, "invalid.json");
        using var store = new JsonConfigurationStore(path, watchForChanges: false);

        var orphan = new ConfigurationDocument
        {
            Nodes = [],
            Rules = [TestProfiles.Rule("Huérfana", TestProfiles.Socks5NodeId, ["teams.exe"])],
        };

        var error = await Assert.ThrowsAsync<ConfigurationStoreException>(
            async () => await store.SaveAsync(orphan));

        Assert.Contains("nodo inexistente", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task Json_LaEscrituraEsAtomica_NoDejaTemporales()
    {
        var path = Path.Combine(_workspace, "atomic.json");
        using var store = new JsonConfigurationStore(path, watchForChanges: false);

        await store.SaveAsync(SampleDocument());

        Assert.True(File.Exists(path));
        Assert.False(File.Exists(path + ".tmp"));
    }

    [Fact]
    public async Task Sqlite_RoundTripPreservaNodosReglasYAjustes()
    {
        using var store = new SqliteConfigurationStore(Path.Combine(_workspace, "config.db"));
        await store.InitializeAsync();

        var original = SampleDocument();
        await store.SaveAsync(original);
        var reloaded = await store.LoadAsync();

        Assert.Equal(original.Nodes.Count, reloaded.Nodes.Count);
        Assert.Equal(original.Rules.Count, reloaded.Rules.Count);
        Assert.Equal(original.Settings, reloaded.Settings);

        var socks = reloaded.Nodes.Single(n => n.Kind == OutboundKind.Socks5);
        Assert.Equal("OCI Frankfurt", socks.Name);
        Assert.Equal(TestProfiles.AdapterNodeId, socks.UpstreamNodeId);
        Assert.Equal(TimeSpan.FromSeconds(10), socks.ConnectTimeout);

        var adapter = reloaded.Nodes.Single(n => n.Kind == OutboundKind.NetworkAdapter);
        Assert.Equal("wg-corp", adapter.Adapter!.InterfaceName);

        var rule = reloaded.Rules.Single();
        Assert.Equal(new[] { "teams.exe", "ms-teams.exe" }, rule.Process.Patterns);
        Assert.Equal(TransportProtocol.Tcp, rule.Target!.Protocol);
        Assert.Equal(new[] { PortRange.Single(443) }, rule.Target.Ports);
    }

    [Fact]
    public async Task Sqlite_GuardarDosVecesReemplazaSinDuplicar()
    {
        using var store = new SqliteConfigurationStore(Path.Combine(_workspace, "idempotent.db"));
        await store.InitializeAsync();

        await store.SaveAsync(SampleDocument());
        await store.SaveAsync(SampleDocument());

        var reloaded = await store.LoadAsync();

        Assert.Equal(2, reloaded.Nodes.Count);
        Assert.Single(reloaded.Rules);
    }

    [Fact]
    public async Task Sqlite_NotificaElCambioParaRecargaEnCaliente()
    {
        using var store = new SqliteConfigurationStore(Path.Combine(_workspace, "notify.db"));
        await store.InitializeAsync();

        ConfigurationDocument? observed = null;
        store.Changed += (_, e) => observed = e.Document;

        await store.SaveAsync(SampleDocument());

        Assert.NotNull(observed);
        Assert.Single(observed!.Rules);
    }

    private static string Canonical(ConfigurationDocument document) =>
        JsonSerializer.Serialize(document, ConfigurationJson.Options);

    private static ConfigurationDocument SampleDocument() => new()
    {
        Nodes = [TestProfiles.AdapterNode(), TestProfiles.Socks5Node(upstream: TestProfiles.AdapterNodeId)],
        Rules =
        [
            TestProfiles.Rule(
                "Colaboración",
                TestProfiles.Socks5NodeId,
                ["teams.exe", "ms-teams.exe"],
                priority: 10,
                target: new TargetSelector
                {
                    Ports = [PortRange.Single(443)],
                    HostPatterns = ["*.teams.microsoft.com"],
                    Protocol = TransportProtocol.Tcp,
                }),
        ],
        Settings = new EngineSettings { BlockQuicForManagedApps = true, WinDivertPriority = -100 },
    };

    public void Dispose() => Directory.Delete(_workspace, recursive: true);
}
