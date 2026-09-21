using System.Net;
using System.Net.Sockets;
using ProxyApp.Abstractions.Configuration;
using ProxyApp.Core.Interception;

namespace ProxyApp.Socks5;

/// <summary>Una fila de tráfico, tal como la pinta el dashboard.</summary>
public sealed record TunnelTrafficUpdate(
    Guid Id,
    DateTimeOffset Time,
    string Process,
    string OriginalDestination,
    string Proxy,
    string Status,
    long SentBytes,
    long ReceivedBytes);

/// <summary>
/// Acepta las conexiones que el filtro desvió al puerto local y las abre
/// contra el SOCKS5 que decidió la regla. Los contadores salen mientras
/// los octetos se mueven, no al cerrar.
/// </summary>
public sealed class TunnelBroker : IDisposable
{
    private readonly TcpListener _listener;
    private int _disposed;

    public TunnelBroker()
    {
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
    }

    public IPEndPoint ListenEndpoint => (IPEndPoint)_listener.LocalEndpoint;

    public event Action<TunnelTrafficUpdate>? TrafficChanged;

    public async Task RunAsync(Func<IPEndPoint, InterceptedFlow?> resolve, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resolve);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        await using var registration = stop.Token.Register(static state => ((TcpListener)state!).Stop(), _listener);

        while (!stop.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(stop.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                break;
            }

            _ = HandleAsync(client, resolve, stop.Token);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _listener.Stop();
    }

    private async Task HandleAsync(TcpClient client, Func<IPEndPoint, InterceptedFlow?> resolve, CancellationToken cancellationToken)
    {
        var id = Guid.NewGuid();
        var time = DateTimeOffset.Now;
        var process = "—";
        var destination = "—";
        var proxy = "—";
        try
        {
            client.NoDelay = true;
            if (client.Client.RemoteEndPoint is not IPEndPoint remote)
            {
                return;
            }

            var flow = resolve(remote);
            if (flow?.Decision.Node is not { } node || string.IsNullOrWhiteSpace(node.Host))
            {
                return;
            }

            process = FileName(flow.ExecutablePath);
            destination = flow.OriginalDestination.ToString();
            proxy = $"{node.Host}:{node.Port}";

            if (node.Kind != OutboundKind.Socks5)
            {
                Publish(new TunnelTrafficUpdate(id, time, process, destination, proxy, "Solo SOCKS5", 0, 0));
                return;
            }

            Publish(new TunnelTrafficUpdate(id, time, process, destination, proxy, "Abierto", 0, 0));

            Socks5Credentials? credentials = null;
            if (node.Credentials is { Username.Length: > 0 } stored)
            {
                credentials = new Socks5Credentials(stored.Username, stored.ProtectedPassword);
            }

            var socks = new Socks5Client(node.Host, node.Port, credentials);
            var target = flow.OriginalDestination.Address.ToString();
            await using var tunnel = await socks.ConnectAsync(target, flow.OriginalDestination.Port, cancellationToken).ConfigureAwait(false);
            IProgress<Socks5RelaySnapshot> progress = new InlineProgress(snapshot =>
                Publish(new TunnelTrafficUpdate(id, time, process, destination, proxy, "Activo", snapshot.BytesToProxy, snapshot.BytesFromProxy)));
            var result = await Socks5Client.RelayAsync(client.GetStream(), tunnel.Stream, progress, cancellationToken).ConfigureAwait(false);
            var status = result.AbruptClose ? "Cortado" : "Cerrado";
            Publish(new TunnelTrafficUpdate(id, time, process, destination, proxy, status, result.BytesToProxy, result.BytesFromProxy));
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            Publish(new TunnelTrafficUpdate(id, time, process, destination, proxy, ex.Message, 0, 0));
        }
        finally
        {
            client.Dispose();
        }
    }

    private void Publish(TunnelTrafficUpdate update) => TrafficChanged?.Invoke(update);

    private sealed class InlineProgress(Action<Socks5RelaySnapshot> report) : IProgress<Socks5RelaySnapshot>
    {
        public void Report(Socks5RelaySnapshot value) => report(value);
    }

    private static string FileName(string path)
    {
        var slash = path.LastIndexOfAny(['\\', '/']);
        return slash < 0 ? path : path[(slash + 1)..];
    }
}
