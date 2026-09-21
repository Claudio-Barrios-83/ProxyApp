using System.Net;
using System.Net.Sockets;
using System.Text;
using ProxyApp.Abstractions.Configuration;
using ProxyApp.Abstractions.Routing;
using ProxyApp.Core.Interception;
using ProxyApp.Socks5;
using Xunit;

namespace ProxyApp.Configuration.Tests;

public sealed class Socks5ClientTests
{
    private static readonly TimeSpan TestBudget = TimeSpan.FromSeconds(5);

    [Fact]
    public async Task Dominio_SeEnviaSinResolver_YElEcoVuelve()
    {
        await using var proxy = new FakeSocks5();
        await using var pair = await AppPair.OpenAsync();
        var client = new Socks5Client("127.0.0.1", proxy.Port, options: Once());

        await using var tunnel = await client.ConnectAsync("teams.microsoft.com", 443);
        var relay = Socks5Client.RelayAsync(pair.Dial.GetStream(), tunnel.Stream);

        await pair.Accepted.GetStream().WriteAsync("hola"u8.ToArray());
        var echo = new byte[4];
        await pair.Accepted.GetStream().ReadExactlyAsync(echo);

        Assert.Equal("hola", Encoding.ASCII.GetString(echo));
        Assert.Equal(0x03, proxy.LastAddressType);
        Assert.Equal("teams.microsoft.com", proxy.LastHost);
        Assert.Equal(443, proxy.LastPort);

        pair.Accepted.Client.Shutdown(SocketShutdown.Send);
        var result = await relay.WaitAsync(TestBudget);
        Assert.Equal(4, result.BytesToProxy);
        Assert.Equal(4, result.BytesFromProxy);
        Assert.False(result.AbruptClose);
    }

    [Fact]
    public async Task IPv4_UsaAtyp01()
    {
        await using var proxy = new FakeSocks5();
        var client = new Socks5Client("127.0.0.1", proxy.Port, options: Once());

        await using var tunnel = await client.ConnectAsync("8.8.8.8", 53);

        Assert.Equal(0x01, proxy.LastAddressType);
        Assert.Equal("8.8.8.8", proxy.LastHost);
        Assert.Equal(53, proxy.LastPort);
        Assert.Equal(IPAddress.Any, tunnel.BoundEndpoint.Address);
    }

    [Fact]
    public async Task UsuarioContrasena_NegociaRfc1929()
    {
        await using var proxy = new FakeSocks5 { Username = "ana", Password = "secreto" };
        var client = new Socks5Client(
            "127.0.0.1",
            proxy.Port,
            new Socks5Credentials("ana", "secreto"),
            Once());

        await using var tunnel = await client.ConnectAsync("slack.com", 443);

        Assert.Equal("ana", proxy.LastUsername);
        Assert.Equal("slack.com", proxy.LastHost);
        _ = tunnel;
    }

    [Fact]
    public async Task ContrasenaRechazada_NoSeReintenta()
    {
        await using var proxy = new FakeSocks5 { Username = "ana", Password = "secreto" };
        var client = new Socks5Client(
            "127.0.0.1",
            proxy.Port,
            new Socks5Credentials("ana", "mal"),
            Once() with { MaxHandshakeAttempts = 3 });

        var error = await Assert.ThrowsAsync<Socks5Exception>(() => client.ConnectAsync("slack.com", 443));

        Assert.Equal(Socks5FailureKind.AuthenticationRejected, error.Kind);
        Assert.False(error.CanRetryHandshake);
        Assert.Equal(1, proxy.Connections);
    }

    [Fact]
    public async Task ConnectRechazado_InformaConnectionRefused()
    {
        await using var proxy = new FakeSocks5 { ConnectReply = 0x05 };
        var client = new Socks5Client("127.0.0.1", proxy.Port, options: Once() with { MaxHandshakeAttempts = 3 });

        var error = await Assert.ThrowsAsync<Socks5Exception>(() => client.ConnectAsync("teams.microsoft.com", 443));

        Assert.Equal(Socks5FailureKind.ConnectionRefused, error.Kind);
        Assert.Equal(Socks5Reply.ConnectionRefused, error.Reply);
        Assert.Equal(1, proxy.Connections);
    }

    [Fact]
    public async Task CorteDuranteElSaludo_SeReintentaUnaVez()
    {
        await using var proxy = new FakeSocks5 { DropFirstConnection = true };
        var client = new Socks5Client(
            "127.0.0.1",
            proxy.Port,
            options: Once() with { MaxHandshakeAttempts = 2, RetryDelay = TimeSpan.FromMilliseconds(20) });

        await using var tunnel = await client.ConnectAsync("example.com", 80);

        Assert.Equal(2, proxy.Connections);
        Assert.Equal("example.com", proxy.LastHost);
        _ = tunnel;
    }

    [Fact]
    public async Task ProxyMudo_AgotaElPlazoDeSaludo()
    {
        await using var proxy = new FakeSocks5 { StallHandshake = true };
        var client = new Socks5Client(
            "127.0.0.1",
            proxy.Port,
            options: Once() with { HandshakeTimeout = TimeSpan.FromMilliseconds(200) });

        var error = await Assert.ThrowsAsync<Socks5Exception>(() => client.ConnectAsync("example.com", 80));

        Assert.Equal(Socks5FailureKind.Timeout, error.Kind);
        Assert.True(error.CanRetryHandshake);
    }

    [Fact]
    public async Task ProxyCaido_EsInalcanzable()
    {
        var port = FreePort();
        var client = new Socks5Client("127.0.0.1", port, options: Once());

        var error = await Assert.ThrowsAsync<Socks5Exception>(() => client.ConnectAsync("example.com", 80));

        Assert.Equal(Socks5FailureKind.ProxyUnreachable, error.Kind);
    }

    [Fact]
    public async Task Broker_ReenviaYPublicaElTrafico()
    {
        await using var proxy = new FakeSocks5();
        var node = TestProfiles.Socks5Node() with { Port = proxy.Port };
        var rule = TestProfiles.Rule("teams", node.Id, ["teams.exe"]);
        var flow = new InterceptedFlow
        {
            ProcessId = 10,
            ExecutablePath = @"C:\Program Files\Teams\teams.exe",
            Client = new IPEndPoint(IPAddress.Loopback, 9),
            OriginalDestination = new IPEndPoint(IPAddress.Parse("52.113.194.132"), 443),
            Decision = RouteDecision.Through(rule, [node]),
            Protocol = TransportProtocol.Tcp,
        };

        using var broker = new TunnelBroker();
        var updates = new List<TunnelTrafficUpdate>();
        broker.TrafficChanged += update =>
        {
            lock (updates)
            {
                updates.Add(update);
            }
        };
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var running = broker.RunAsync(_ => flow, cts.Token);

        using var app = new TcpClient();
        await app.ConnectAsync(IPAddress.Loopback, broker.ListenEndpoint.Port);
        await app.GetStream().WriteAsync("ping"u8.ToArray());
        var echo = new byte[4];
        await app.GetStream().ReadExactlyAsync(echo);

        Assert.Equal("ping", Encoding.ASCII.GetString(echo));
        app.Client.Shutdown(SocketShutdown.Send);

        TunnelTrafficUpdate? closed = null;
        for (var i = 0; i < 40 && closed is null; i++)
        {
            await Task.Delay(50);
            lock (updates)
            {
                closed = updates.Find(item => item.Status == "Cerrado");
            }
        }

        Assert.NotNull(closed);
        Assert.Equal("teams.exe", closed.Process);
        Assert.Equal("52.113.194.132:443", closed.OriginalDestination);
        Assert.Equal($"127.0.0.1:{proxy.Port}", closed.Proxy);
        Assert.True(closed.SentBytes >= 4);
        Assert.True(closed.ReceivedBytes >= 4);
        cts.Cancel();
        await running.WaitAsync(TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task Broker_SalePorElAdaptadorNombrado()
    {
        using var echo = new TcpListener(IPAddress.Loopback, 0);
        echo.Start();
        var echoPort = ((IPEndPoint)echo.LocalEndpoint).Port;
        var accepted = echo.AcceptTcpClientAsync();

        var node = TestProfiles.AdapterNode();
        var rule = TestProfiles.Rule("teams", node.Id, ["teams.exe"]);
        var flow = new InterceptedFlow
        {
            ProcessId = 10,
            ExecutablePath = @"C:\Program Files\Teams\teams.exe",
            Client = new IPEndPoint(IPAddress.Loopback, 9),
            OriginalDestination = new IPEndPoint(IPAddress.Loopback, echoPort),
            Decision = RouteDecision.Through(rule, [node]),
            Protocol = TransportProtocol.Tcp,
        };

        uint? seen = null;
        using var broker = new TunnelBroker(_ => 15, (_, index) => seen = index);
        var updates = new List<TunnelTrafficUpdate>();
        broker.TrafficChanged += update =>
        {
            lock (updates)
            {
                updates.Add(update);
            }
        };
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var running = broker.RunAsync(_ => flow, cts.Token);

        using var app = new TcpClient();
        await app.ConnectAsync(IPAddress.Loopback, broker.ListenEndpoint.Port);
        await app.GetStream().WriteAsync("ping"u8.ToArray());
        using var server = await accepted;
        var inbound = new byte[4];
        await server.GetStream().ReadExactlyAsync(inbound);
        await server.GetStream().WriteAsync(inbound);
        var echoBack = new byte[4];
        await app.GetStream().ReadExactlyAsync(echoBack);

        Assert.Equal("ping", Encoding.ASCII.GetString(echoBack));
        Assert.Equal(15u, seen);
        cts.Cancel();
        server.Dispose();
        echo.Stop();
        await running.WaitAsync(TimeSpan.FromSeconds(2));
    }

    private static Socks5ClientOptions Once() => new()
    {
        MaxHandshakeAttempts = 1,
        ConnectTimeout = TestBudget,
        HandshakeTimeout = TestBudget,
    };

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private sealed class AppPair : IAsyncDisposable
    {
        private AppPair(TcpListener listener, TcpClient dial, TcpClient accepted)
        {
            Listener = listener;
            Dial = dial;
            Accepted = accepted;
        }

        private TcpListener Listener { get; }

        public TcpClient Dial { get; }

        public TcpClient Accepted { get; }

        public static async Task<AppPair> OpenAsync()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var dial = new TcpClient();
            var connect = dial.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
            var accepted = await listener.AcceptTcpClientAsync();
            await connect;
            return new AppPair(listener, dial, accepted);
        }

        public async ValueTask DisposeAsync()
        {
            Accepted.Dispose();
            Dial.Dispose();
            Listener.Stop();
            await Task.CompletedTask;
        }
    }

    private sealed class FakeSocks5 : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _loop;

        public FakeSocks5()
        {
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _loop = Task.Run(AcceptLoopAsync);
        }

        public int Port { get; }

        public int Connections { get; private set; }

        public byte LastAddressType { get; private set; }

        public string? LastHost { get; private set; }

        public int LastPort { get; private set; }

        public string? LastUsername { get; private set; }

        public string? Username { get; init; }

        public string? Password { get; init; }

        public byte ConnectReply { get; init; }

        public bool DropFirstConnection { get; init; }

        public bool StallHandshake { get; init; }

        public async ValueTask DisposeAsync()
        {
            await _stop.CancelAsync();
            _listener.Stop();
            try
            {
                await _loop.WaitAsync(TimeSpan.FromSeconds(2));
            }
            catch (Exception ex) when (ex is OperationCanceledException or TimeoutException or SocketException or ObjectDisposedException)
            {
            }

            _stop.Dispose();
        }

        private async Task AcceptLoopAsync()
        {
            while (!_stop.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(_stop.Token);
                }
                catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException or InvalidOperationException)
                {
                    break;
                }

                Connections++;
                try
                {
                    await HandleAsync(client);
                }
                catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or EndOfStreamException)
                {
                }
                finally
                {
                    client.Dispose();
                }
            }
        }

        private async Task HandleAsync(TcpClient client)
        {
            if (DropFirstConnection && Connections == 1)
            {
                return;
            }

            if (StallHandshake)
            {
                await Task.Delay(Timeout.Infinite, _stop.Token);
            }

            var stream = client.GetStream();
            var greeting = new byte[2];
            await stream.ReadExactlyAsync(greeting);
            var methods = new byte[greeting[1]];
            await stream.ReadExactlyAsync(methods);

            if (Username is null)
            {
                await stream.WriteAsync(new byte[] { 0x05, 0x00 });
            }
            else
            {
                await stream.WriteAsync(new byte[] { 0x05, 0x02 });
                var version = new byte[1];
                await stream.ReadExactlyAsync(version);
                var userLength = new byte[1];
                await stream.ReadExactlyAsync(userLength);
                var user = new byte[userLength[0]];
                await stream.ReadExactlyAsync(user);
                var passLength = new byte[1];
                await stream.ReadExactlyAsync(passLength);
                var pass = new byte[passLength[0]];
                await stream.ReadExactlyAsync(pass);
                LastUsername = Encoding.UTF8.GetString(user);
                var ok = LastUsername == Username && Encoding.UTF8.GetString(pass) == Password;
                await stream.WriteAsync(new byte[] { 0x01, ok ? (byte)0x00 : (byte)0x01 });
                if (!ok)
                {
                    return;
                }
            }

            var head = new byte[4];
            await stream.ReadExactlyAsync(head);
            LastAddressType = head[3];
            if (head[3] == 0x03)
            {
                var length = new byte[1];
                await stream.ReadExactlyAsync(length);
                var host = new byte[length[0]];
                await stream.ReadExactlyAsync(host);
                LastHost = Encoding.ASCII.GetString(host);
            }
            else
            {
                var address = new byte[head[3] == 0x04 ? 16 : 4];
                await stream.ReadExactlyAsync(address);
                LastHost = new IPAddress(address).ToString();
            }

            var port = new byte[2];
            await stream.ReadExactlyAsync(port);
            LastPort = (port[0] << 8) | port[1];

            await stream.WriteAsync(new byte[] { 0x05, ConnectReply, 0x00, 0x01, 0, 0, 0, 0, 0, 0 });
            if (ConnectReply != 0x00)
            {
                return;
            }

            var buffer = new byte[1024];
            while (true)
            {
                var read = await stream.ReadAsync(buffer);
                if (read == 0)
                {
                    break;
                }

                await stream.WriteAsync(buffer.AsMemory(0, read));
            }
        }
    }
}
