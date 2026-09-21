using ProxyApp.Core.Rules;
using Xunit;

namespace ProxyApp.Configuration.Tests;

public sealed class GetProxyForProcessTests
{
    private static readonly Proxy Socks = new()
    {
        Type = ProxyType.Socks5,
        Host = "10.8.0.1",
        Port = 1080,
        Auth = new ProxyAuth { Username = "ana", Password = "secreto" },
    };

    private static readonly Proxy Http = new()
    {
        Type = ProxyType.Http,
        Host = "proxy.interno",
        Port = 8080,
    };

    [Theory]
    [InlineData("teams.exe")]
    [InlineData("TEAMS.EXE")]
    [InlineData(@"C:\Program Files\Teams\teams.exe")]
    public void NombreDeEjecutable_DevuelveElProxy(string processName)
    {
        var engine = Engine(Rule("teams.exe", Socks));

        var proxy = engine.GetProxyForProcess(processName, "52.113.194.132", 443);

        Assert.Equal(Socks, proxy);
    }

    [Theory]
    [InlineData("ms-teams.exe", true)]
    [InlineData("teams-classic.exe", true)]
    [InlineData("chrome.exe", false)]
    public void Comodin_CasaSoloElPatron(string processName, bool matches)
    {
        var engine = Engine(Rule("*teams*", Socks));

        var proxy = engine.GetProxyForProcess(processName, "1.1.1.1", 443);

        Assert.Equal(matches ? Socks : Proxy.Direct, proxy);
    }

    [Fact]
    public void SinRegla_DevuelveDirect()
    {
        var engine = new RoutingRuleEngine();

        Assert.Same(Proxy.Direct, engine.GetProxyForProcess("notepad.exe", "8.8.8.8", 53));
    }

    [Fact]
    public void ReglaDesactivada_DevuelveDirect()
    {
        var engine = Engine(Rule("chrome.exe", Http) with { IsEnabled = false });

        Assert.Same(Proxy.Direct, engine.GetProxyForProcess("chrome.exe", "8.8.8.8", 443));
    }

    [Theory]
    [InlineData("192.168.1.20")]
    [InlineData("10.1.1.5")]
    public void BypassLocalNetwork_OmiteElProxyEnLan(string targetIp)
    {
        var engine = Engine(Rule("teams.exe", Socks) with { BypassLocalNetwork = true });

        Assert.Same(Proxy.Direct, engine.GetProxyForProcess("teams.exe", targetIp, 443));
    }

    [Fact]
    public void SinBypass_LaLanTambienVaAlProxy()
    {
        var engine = Engine(Rule("teams.exe", Socks) with { BypassLocalNetwork = false });

        Assert.Equal(Socks, engine.GetProxyForProcess("teams.exe", "192.168.1.20", 443));
    }

    [Fact]
    public void GanaLaPrimeraRegla()
    {
        var engine = Engine(
            Rule("teams.exe", Socks),
            Rule("*", Http));

        Assert.Equal(Socks, engine.GetProxyForProcess("teams.exe", "8.8.8.8", 443));
        Assert.Equal(Http, engine.GetProxyForProcess("chrome.exe", "8.8.8.8", 443));
    }

    [Fact]
    public void Json_RoundTripConservaElMatching()
    {
        var path = Path.Combine(Path.GetTempPath(), $"proxyapp-rules-{Guid.NewGuid():N}.json");
        try
        {
            var original = Engine(Rule("teams.exe", Socks), Rule("chrome.exe", Http) with { IsEnabled = false });
            original.SaveRulesToJson(path);

            var loaded = new RoutingRuleEngine();
            loaded.LoadRulesFromJson(path);

            Assert.Equal(Socks, loaded.GetProxyForProcess("teams.exe", "8.8.8.8", 443));
            Assert.Same(Proxy.Direct, loaded.GetProxyForProcess("chrome.exe", "8.8.8.8", 443));
            Assert.False(File.Exists(path + ".tmp"));
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    private static RoutingRuleEngine Engine(params Rule[] rules) => new(rules);

    private static Rule Rule(string processName, Proxy proxy) => new()
    {
        RuleId = Guid.NewGuid(),
        ProcessName = processName,
        TargetProxy = proxy,
    };
}
