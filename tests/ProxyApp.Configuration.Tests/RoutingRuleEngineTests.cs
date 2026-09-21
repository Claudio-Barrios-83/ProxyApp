using ProxyApp.Abstractions.Configuration;
using ProxyApp.Abstractions.Routing;
using ProxyApp.Core.Rules;
using Xunit;

namespace ProxyApp.Configuration.Tests;

public sealed class RoutingRuleEngineTests
{
    [Fact]
    public void SinReglas_DevuelveDirecto()
    {
        var engine = new RoutingRuleEngine(ConfigurationDocument.Empty);

        var decision = engine.Evaluate(TestProfiles.Connection("C:\\Apps\\teams.exe"));

        Assert.Equal(RouteAction.Direct, decision.Action);
        Assert.Null(decision.MatchedRule);
    }

    [Theory]
    [InlineData("C:\\Apps\\teams.exe", true)]
    [InlineData("C:\\Otro\\TEAMS.EXE", true)]
    [InlineData("C:\\Apps\\slack.exe", true)]
    [InlineData("C:\\Apps\\notepad.exe", false)]
    public void MatchPorNombreDeEjecutable_IgnoraMayusculas(string executable, bool shouldMatch)
    {
        var engine = Build(TestProfiles.Rule("Colaboración", TestProfiles.Socks5NodeId, ["teams.exe", "slack.exe"]));

        var decision = engine.Evaluate(TestProfiles.Connection(executable));

        Assert.Equal(shouldMatch ? RouteAction.Proxy : RouteAction.Direct, decision.Action);
    }

    [Theory]
    [InlineData("C:\\Apps\\ms-teams.exe", true)]
    [InlineData("C:\\Apps\\teams-classic.exe", true)]
    [InlineData("C:\\Apps\\zoom.exe", false)]
    public void MatchConComodines(string executable, bool shouldMatch)
    {
        var engine = Build(TestProfiles.Rule("Comodín", TestProfiles.Socks5NodeId, ["*teams*.exe"]));

        var decision = engine.Evaluate(TestProfiles.Connection(executable));

        Assert.Equal(shouldMatch, decision.Action == RouteAction.Proxy);
    }

    [Fact]
    public void MatchPorRutaCompleta_DistingueBinariosHomonimos()
    {
        var engine = Build(TestProfiles.Rule(
            "Solo el Chrome de Program Files",
            TestProfiles.Socks5NodeId,
            ["C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"]));

        var oficial = engine.Evaluate(TestProfiles.Connection("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"));
        var portable = engine.Evaluate(TestProfiles.Connection("D:\\Portable\\chrome.exe"));

        Assert.Equal(RouteAction.Proxy, oficial.Action);
        Assert.Equal(RouteAction.Direct, portable.Action);
    }

    [Fact]
    public void GanaLaReglaDeMenorPrioridad()
    {
        var engine = Build(
            TestProfiles.Rule("Bloqueo genérico", TestProfiles.BlockNodeId, ["*"], priority: 100),
            TestProfiles.Rule("Teams al proxy", TestProfiles.Socks5NodeId, ["teams.exe"], priority: 10));

        var decision = engine.Evaluate(TestProfiles.Connection("C:\\Apps\\teams.exe"));

        Assert.Equal(RouteAction.Proxy, decision.Action);
        Assert.Equal("Teams al proxy", decision.MatchedRule!.Name);
    }

    [Fact]
    public void ReglaDesactivada_NoSeEvalua()
    {
        var engine = Build(TestProfiles.Rule("Apagada", TestProfiles.Socks5NodeId, ["teams.exe"], enabled: false));

        Assert.Equal(RouteAction.Direct, engine.Evaluate(TestProfiles.Connection("C:\\Apps\\teams.exe")).Action);
    }

    [Fact]
    public void NodoDesactivado_DegradaADirecto()
    {
        var document = new ConfigurationDocument
        {
            Nodes = [TestProfiles.Socks5Node() with { IsEnabled = false }],
            Rules = [TestProfiles.Rule("Teams", TestProfiles.Socks5NodeId, ["teams.exe"])],
        };
        var engine = new RoutingRuleEngine(document);

        var decision = engine.Evaluate(TestProfiles.Connection("C:\\Apps\\teams.exe"));

        Assert.Equal(RouteAction.Direct, decision.Action);
        Assert.Contains("desactivado", decision.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("192.168.1.50", RouteAction.Direct)]
    [InlineData("10.20.30.40", RouteAction.Direct)]
    [InlineData("127.0.0.1", RouteAction.Direct)]
    [InlineData("52.113.194.132", RouteAction.Proxy)]
    public void BypassPrivateNetworks_DejaPasarLaLan(string remote, RouteAction expected)
    {
        var engine = Build(TestProfiles.Rule("Teams", TestProfiles.Socks5NodeId, ["teams.exe"]));

        var decision = engine.Evaluate(TestProfiles.Connection("C:\\Apps\\teams.exe", remote));

        Assert.Equal(expected, decision.Action);
    }

    [Fact]
    public void SinBypass_LaLanTambienVaPorElProxy()
    {
        var engine = Build(TestProfiles.Rule("Todo", TestProfiles.Socks5NodeId, ["teams.exe"], bypassPrivate: false));

        var decision = engine.Evaluate(TestProfiles.Connection("C:\\Apps\\teams.exe", "192.168.1.50"));

        Assert.Equal(RouteAction.Proxy, decision.Action);
    }

    [Fact]
    public void FiltroPorPuertoYProtocolo()
    {
        var target = new TargetSelector
        {
            Ports = [PortRange.Single(443), PortRange.Parse("8000-8100")],
            Protocol = TransportProtocol.Tcp,
        };
        var engine = Build(TestProfiles.Rule("Solo HTTPS", TestProfiles.Socks5NodeId, ["teams.exe"], target: target));

        Assert.Equal(RouteAction.Proxy, engine.Evaluate(TestProfiles.Connection("teams.exe", remotePort: 443)).Action);
        Assert.Equal(RouteAction.Proxy, engine.Evaluate(TestProfiles.Connection("teams.exe", remotePort: 8050)).Action);
        Assert.Equal(RouteAction.Direct, engine.Evaluate(TestProfiles.Connection("teams.exe", remotePort: 25)).Action);
        Assert.Equal(
            RouteAction.Direct,
            engine.Evaluate(TestProfiles.Connection("teams.exe", remotePort: 443, protocol: TransportProtocol.Udp)).Action);
    }

    [Fact]
    public void FiltroPorHost_UsaElFqdnCuandoSeConoce()
    {
        var target = new TargetSelector { HostPatterns = ["*.teams.microsoft.com"] };
        var engine = Build(TestProfiles.Rule("Teams SaaS", TestProfiles.Socks5NodeId, ["teams.exe"], target: target));

        var conFqdn = engine.Evaluate(TestProfiles.Connection("teams.exe", remoteHost: "api.teams.microsoft.com"));
        var sinFqdn = engine.Evaluate(TestProfiles.Connection("teams.exe"));

        Assert.Equal(RouteAction.Proxy, conFqdn.Action);
        Assert.Equal(RouteAction.Direct, sinFqdn.Action);
    }

    [Fact]
    public void FiltroPorCidr()
    {
        var target = new TargetSelector { IpRanges = ["52.112.0.0/14"] };
        var engine = Build(TestProfiles.Rule("Rango de Microsoft", TestProfiles.Socks5NodeId, ["teams.exe"], target: target));

        Assert.Equal(RouteAction.Proxy, engine.Evaluate(TestProfiles.Connection("teams.exe", "52.113.194.132")).Action);
        Assert.Equal(RouteAction.Direct, engine.Evaluate(TestProfiles.Connection("teams.exe", "8.8.8.8")).Action);
    }

    [Fact]
    public void ReglaConSid_SoloAplicaAEseUsuario()
    {
        const string Sid = "S-1-5-21-1111111111-2222222222-3333333333-1001";
        var engine = Build(TestProfiles.Rule("Solo Ana", TestProfiles.Socks5NodeId, ["teams.exe"], userSid: Sid));

        Assert.Equal(RouteAction.Proxy, engine.Evaluate(TestProfiles.Connection("teams.exe", userSid: Sid)).Action);
        Assert.Equal(RouteAction.Direct, engine.Evaluate(TestProfiles.Connection("teams.exe", userSid: "S-1-5-18")).Action);
    }

    [Fact]
    public void NodoDeBloqueo_RechazaLaConexion()
    {
        var document = new ConfigurationDocument
        {
            Nodes = [TestProfiles.BlockNode()],
            Rules = [TestProfiles.Rule("Telemetría fuera", TestProfiles.BlockNodeId, ["*"], bypassPrivate: false)],
        };
        var engine = new RoutingRuleEngine(document);

        Assert.Equal(RouteAction.Block, engine.Evaluate(TestProfiles.Connection("cualquiera.exe")).Action);
    }

    [Fact]
    public void NodoDeAdaptador_DevuelveBindAdapter()
    {
        var document = new ConfigurationDocument
        {
            Nodes = [TestProfiles.AdapterNode()],
            Rules = [TestProfiles.Rule("Chrome por WireGuard", TestProfiles.AdapterNodeId, ["chrome.exe"])],
        };
        var engine = new RoutingRuleEngine(document);

        var decision = engine.Evaluate(TestProfiles.Connection("chrome.exe"));

        Assert.Equal(RouteAction.BindAdapter, decision.Action);
        Assert.Equal("wg-corp", decision.Node!.Adapter!.InterfaceName);
    }

    [Fact]
    public void CadenaSocks5SobreWireGuard_SeResuelveEnOrden()
    {
        var document = new ConfigurationDocument
        {
            Nodes = [TestProfiles.AdapterNode(), TestProfiles.Socks5Node(upstream: TestProfiles.AdapterNodeId)],
            Rules = [TestProfiles.Rule("Teams", TestProfiles.Socks5NodeId, ["teams.exe"])],
        };
        var engine = new RoutingRuleEngine(document);

        var decision = engine.Evaluate(TestProfiles.Connection("teams.exe"));

        Assert.Equal(RouteAction.Proxy, decision.Action);
        Assert.Equal(2, decision.Chain.Count);
        Assert.Equal(OutboundKind.Socks5, decision.Chain[0].Kind);
        Assert.Equal(OutboundKind.NetworkAdapter, decision.Chain[1].Kind);
    }

    [Fact]
    public void PublishReemplazaLaConfiguracionEnCaliente()
    {
        var engine = Build(TestProfiles.Rule("Teams", TestProfiles.Socks5NodeId, ["teams.exe"]));
        Assert.Equal(RouteAction.Proxy, engine.Evaluate(TestProfiles.Connection("teams.exe")).Action);

        engine.Publish(ConfigurationDocument.Empty);

        Assert.Equal(RouteAction.Direct, engine.Evaluate(TestProfiles.Connection("teams.exe")).Action);
        Assert.Equal(0, engine.ActiveRuleCount);
    }

    private static RoutingRuleEngine Build(params AppRule[] rules) =>
        new(new ConfigurationDocument
        {
            Nodes = [TestProfiles.Socks5Node(), TestProfiles.AdapterNode(), TestProfiles.BlockNode()],
            Rules = rules,
        });
}
