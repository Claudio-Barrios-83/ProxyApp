using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using ProxyApp.Abstractions.Configuration;
using ProxyApp.Core.Interception;
using ProxyApp.Core.Rules;
using SharpDivert;

namespace ProxyApp.Interception;

/// <summary>
/// Secuestra el tráfico IPv4 saliente de los procesos que casan con una regla y
/// lo entrega a un listener local. El listener, no este filtro, habla SOCKS5 o
/// HTTP CONNECT con el <see cref="OutboundNode"/> que decidió el motor de reglas.
/// </summary>
/// <remarks>
/// <para>
/// El destino que se escribe en el paquete es el puerto donde acepta nuestro
/// listener (<see cref="PacketPipeline.TcpRedirect"/>), nunca la dirección del
/// proxy configurado. Si el SYN de Teams se reescribiera directamente a
/// <c>127.0.0.1:1080</c>, el servidor SOCKS recibiría el ClientHello de la
/// aplicación donde espera la versión 0x05 del RFC 1928, y la aplicación
/// recibiría la respuesta SOCKS donde espera el saludo de su propio protocolo.
/// </para>
/// <para>
/// Handshake TCP. Los números de secuencia no se tocan: la sesión TCP termina
/// en el listener y el túnel hacia el proxy es otra sesión distinta.
/// </para>
/// <list type="number">
/// <item>
/// La app llama a <c>connect(servidor:443)</c>. La pila crea una TCB indexada
/// por <c>(ipLocal, puertoEfímero, servidor, 443)</c> y emite un SYN con el
/// bit ACK apagado. El estado local pasa a SYN_SENT.
/// </item>
/// <item>
/// Este filtro retiene ese SYN hasta conocer el PID (la capa SOCKET no llega
/// siempre primero). Si la regla casa, reescribe solo el destino a
/// <c>127.0.0.1:puertoListener</c>, lo marca loopback y lo reinyecta saliente.
/// El origen no se cambia: el listener tiene que ver la IP real de la app.
/// </item>
/// <item>
/// El listener responde con un SYN-ACK propio, origen
/// <c>127.0.0.1:puertoListener</c> y ACK igual al ISN de la app más uno.
/// </item>
/// <item>
/// Ese SYN-ACK se captura como paquete nuevo (no es una reinyección, así que
/// el handle sí lo ve). Se restaura el origen al servidor original y se
/// reinyecta <b>entrante</b>. Si se dejara saliente, Windows lo enrutaría
/// hacia la NIC y la TCB, que espera el segmento por el lado de entrada,
/// lo ignoraría. El SYN_SENT nunca avanzaría.
/// </item>
/// <item>
/// La app confirma con un ACK. Lo volvemos a traducir hacia el listener y las
/// dos pilas quedan en ESTABLISHED, convencidas cada una de hablar con la otra.
/// A partir de ahí los datos se copian en el túnel, ya fuera de este filtro.
/// </item>
/// </list>
/// <para>
/// Checksums. Tras mover una dirección, el checksum TCP anterior no sirve
/// aunque el puerto no hubiera cambiado: la pseudo-cabecera incluye las dos
/// IP, el protocolo y la longitud del segmento (RFC 793). Además WinDivert
/// suele entregar el paquete con el campo a cero y <c>IPChecksum == false</c>
/// por el offload de la NIC. <see cref="InternetChecksum"/> deja el valor
/// correcto en el buffer y <see cref="WinDivert.CalcChecksums"/> lo confirma
/// y enciende las marcas de la <c>WINDIVERT_ADDRESS</c>. Con la marca
/// encendida y el campo viejo, <c>WinDivertSend</c> se fía del campo y el
/// peer tira el segmento.
/// </para>
/// </remarks>
public sealed class ProcessNetworkFilter : IDisposable
{
    private const string SocketEvents = "(event == CONNECT or event == CLOSE) and (tcp or udp)";

    private readonly PacketPipeline _pipeline;
    private readonly SocketProcessMap _sockets = new();
    private readonly IProcessIdentityResolver _identities;
    private readonly EngineSettings _settings;
    private readonly IFilterTrace? _trace;
    private readonly CancellationTokenSource _stop = new();
    private readonly object _sendGate = new();
    private readonly int _engineProcessId;
    private readonly IPEndPoint _tcpRedirect;

    private WinDivert? _network;
    private WinDivert? _socketHandle;
    private readonly List<WinDivert> _flowHandles = [];
    private readonly HashSet<string> _capturedClients = [];
    private readonly object _widenGate = new();
    private int _started;
    private long _seen;

    public ProcessNetworkFilter(
        RoutingRuleEngine rules,
        IPEndPoint tcpRedirect,
        IProcessIdentityResolver identities,
        IConnectionPidResolver? connectionPids = null,
        Func<IReadOnlyList<IPEndPoint>>? passthroughEndpoints = null,
        EngineSettings? settings = null,
        IPEndPoint? udpRelay = null,
        int? engineProcessId = null,
        IFilterTrace? trace = null)
    {
        ArgumentNullException.ThrowIfNull(identities);

        _settings = settings ?? new EngineSettings();
        _engineProcessId = engineProcessId ?? Environment.ProcessId;
        _identities = identities;
        _ = connectionPids;
        _trace = trace;
        _tcpRedirect = tcpRedirect;
        _pipeline = new PacketPipeline(
            rules,
            tcpRedirect,
            _engineProcessId,
            _settings.BlockQuicForManagedApps,
            udpRelay,
            passthroughEndpoints);
    }

    public event Action<InterceptedFlow>? FlowOpened
    {
        add => _pipeline.FlowOpened += value;
        remove => _pipeline.FlowOpened -= value;
    }

    public int ActiveFlowCount => _pipeline.Flows.Count;

    /// <summary>
    /// Solo el SYN inicial, las respuestas del listener y los clientes ya
    /// desviados. ProtonVPN habla TCP al conectar: si capturamos todo el TCP
    /// de la máquina, esa negociación entra en nuestra cola y la VPN no sube.
    /// </summary>
    public static string BuildNetworkFilter(IPEndPoint redirect, IReadOnlyList<IPEndPoint>? clients = null)
    {
        ArgumentNullException.ThrowIfNull(redirect);
        var clauses = new List<string> { "(tcp.Syn and not tcp.Ack)" };
        if (redirect.Address.AddressFamily == AddressFamily.InterNetwork)
        {
            clauses.Add($"(ip.SrcAddr == {redirect.Address} and tcp.SrcPort == {redirect.Port})");
        }

        if (clients is not null)
        {
            foreach (var client in clients)
            {
                if (client.Address.AddressFamily == AddressFamily.InterNetwork && client.Port > 0)
                {
                    clauses.Add($"(ip.SrcAddr == {client.Address} and tcp.SrcPort == {client.Port})");
                }
            }
        }

        return $"outbound and ip and tcp and ({string.Join(" or ", clauses)})";
    }

    /// <summary>
    /// Lo consulta el listener al aceptar. La clave es el extremo remoto del
    /// socket aceptado, que es la IP y el puerto efímero de la aplicación.
    /// </summary>
    public bool TryGetSession(IPEndPoint client, TransportProtocol protocol, out InterceptedFlow? flow)
    {
        ArgumentNullException.ThrowIfNull(client);
        var found = _pipeline.Flows.TryGet(protocol, client.Address, client.Port, out var existing);
        flow = found ? existing : null;
        return found;
    }

    /// <summary>Bloquea hasta que se cancela <paramref name="cancellationToken"/> o se llama a <see cref="Dispose"/>.</summary>
    public void Run(CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref _started, 1) != 0)
        {
            throw new InvalidOperationException("El filtro ya está en marcha.");
        }

        // La capa SOCKET tiene que ir en modo sniff. Esos eventos no se pueden
        // reinyectar: abrir el handle sin sniff dejaría colgado cada connect()
        // de la máquina. La capa NETWORK sí desvía, porque el paquete hay que
        // modificarlo antes de devolverlo.
        try
        {
            _socketHandle = new WinDivert(SocketEvents, WinDivert.Layer.Socket, 0, WinDivert.Flag.Sniff | WinDivert.Flag.RecvOnly);
            _network = OpenNetwork(BuildNetworkFilter(_tcpRedirect));
        }
        catch
        {
            Shutdown(_socketHandle);
            _socketHandle = null;
            throw;
        }

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stop.Token);
        var token = linked.Token;
        var socketThread = new Thread(() => SocketLoop(_socketHandle, token))
        {
            IsBackground = true,
            Name = "ProxyApp.SocketMap",
        };
        socketThread.Start();

        _trace?.Info($"Filtro de red: {BuildNetworkFilter(_tcpRedirect)}");

        var buffer = new byte[0xFFFF];
        var addresses = new WinDivertAddress[1];

        try
        {
            while (!token.IsCancellationRequested)
            {
                var (received, addressCount) = _network.RecvEx(buffer, addresses);
                if (received == 0 || addressCount == 0)
                {
                    continue;
                }

                Handle(_network, buffer.AsSpan(0, (int)received), addresses[0]);
                if ((ActiveFlowCount & 127) == 0)
                {
                    _pipeline.Sweep(DateTime.UtcNow);
                }
            }
        }
        catch (WinDivertException) when (token.IsCancellationRequested)
        {
            // ShutdownRecv desbloquea RecvEx con error. Es la salida normal.
        }
        finally
        {
            try
            {
                socketThread.Join(TimeSpan.FromSeconds(2));
            }
            catch (WinDivertException)
            {
            }
        }
    }

    public void Dispose()
    {
        _stop.Cancel();
        Shutdown(_socketHandle);
        Shutdown(_network);
        lock (_widenGate)
        {
            foreach (var handle in _flowHandles)
            {
                Shutdown(handle);
            }

            _flowHandles.Clear();
        }

        _stop.Dispose();
    }

    private void Handle(WinDivert network, ReadOnlySpan<byte> packet, WinDivertAddress address)
    {
        if (!Ipv4Packet.TryParse(packet, out var parsed))
        {
            Send(network, packet, address);
            return;
        }

        var before = _pipeline.Flows.Count;
        var plan = _pipeline.Decide(parsed, () => ResolvePid(parsed), _identities.TryResolve);
        Interlocked.Increment(ref _seen);
        if (parsed.Protocol == TransportProtocol.Tcp && parsed.IsInitialSyn)
        {
            LogSyn(parsed, plan);
        }

        Apply(network, packet, address, plan);

        // El SYN ya se reinyectó por el handle que lo capturó. El ACK siguiente
        // sale hacia el servidor real: hay que ampliar el filtro ahora, no después.
        if (plan.Fate == PacketFate.ReinjectModified && _pipeline.Flows.Count > before)
        {
            WidenCapture();
        }
    }

    /// <summary>
    /// Cada intento de conexión nueva deja una línea. Es la única forma de
    /// saber por qué un programa no aparece en el panel: o no casa la regla, o
    /// no se resolvió el proceso, o la decisión fue dejarlo directo.
    /// </summary>
    private void LogSyn(ParsedIpv4Packet packet, PacketPlan plan)
    {
        if (_trace is null)
        {
            return;
        }

        var pid = ResolvePid(packet);
        var exe = pid is null ? "proceso sin identificar" : _identities.TryResolve(pid.Value)?.ExecutablePath ?? $"pid {pid}";
        _trace.Info($"SYN {packet.Source}:{packet.SourcePort} -> {packet.Destination}:{packet.DestinationPort} | {exe} | {plan.Fate}");
    }

    private void Apply(WinDivert network, ReadOnlySpan<byte> packet, WinDivertAddress address, PacketPlan plan)
    {
        switch (plan.Fate)
        {
            case PacketFate.Drop:
                _trace?.Info("Paquete descartado por regla de bloqueo.");
                return;

            case PacketFate.ReinjectUnchanged:
                Send(network, packet, address);
                return;

            case PacketFate.ReinjectModified:
                break;

            default:
                Send(network, packet, address);
                return;
        }

        var rented = ArrayPool<byte>.Shared.Rent(packet.Length);
        try
        {
            packet.CopyTo(rented);
            var rewritten = rented.AsSpan(0, packet.Length);

            // La ida solo trae destino nuevo. La vuelta solo trae origen nuevo,
            // que es el servidor que la aplicación cree estar contactando.
            Ipv4Packet.RewriteEndpoints(
                rewritten,
                plan.NewSource,
                plan.NewSourcePort,
                plan.NewDestination,
                plan.NewDestinationPort);

            // Complemento a uno sobre la cabecera IP (con el campo a cero) y
            // sobre pseudo-cabecera + segmento TCP/UDP. El helper nativo repite
            // el cálculo y deja las marcas *Checksum a 1, que es lo que
            // WinDivertSend consulta para no tratar el paquete como offload.
            InternetChecksum.Apply(rewritten);
            WinDivert.CalcChecksums(rewritten, ref address, default);
            address.Outbound = !plan.InjectInbound;
            address.Loopback = plan.MarkLoopback;
            Send(network, rewritten, address);
        }
        catch (ArgumentException ex)
        {
            // Checksum imposible de cerrar: devolver el paquete original evita
            // dejar la conexión colgada dentro del filtro.
            _trace?.Failure("No se pudo recalcular el checksum. El paquete sale sin traducir.", ex);
            Send(network, packet, address);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    /// <summary>
    /// El PID de un SYN lo da la capa SOCKET. Recorrer GetExtendedTcpTable
    /// aquí era el camino lento: cada SYN de Chrome o Teams copiaba la tabla
    /// TCP de Windows en el hilo que drena WinDivert, y el driver empezaba
    /// a descartar. Proton se quedaba en "Conectando".
    /// </summary>
    private int? ResolvePid(ParsedIpv4Packet packet)
    {
        if (_sockets.TryGet(
                packet.Protocol,
                packet.Source,
                packet.SourcePort,
                packet.Destination,
                packet.DestinationPort,
                out var processId))
        {
            return processId;
        }

        return null;
    }

    private void WidenCapture()
    {
        foreach (var client in _pipeline.Flows.Clients())
        {
            var key = string.Create(CultureInfo.InvariantCulture, $"{client.Address}:{client.Port}");
            lock (_widenGate)
            {
                if (!_capturedClients.Add(key))
                {
                    continue;
                }
            }

            var filter = string.Create(
                CultureInfo.InvariantCulture,
                $"outbound and ip and tcp and ip.SrcAddr == {client.Address} and tcp.SrcPort == {client.Port}");
            try
            {
                var handle = OpenNetwork(filter);
                lock (_widenGate)
                {
                    _flowHandles.Add(handle);
                }

                var thread = new Thread(() => FlowLoop(handle))
                {
                    IsBackground = true,
                    Name = "ProxyApp.Flow." + client.Port,
                };
                thread.Start();
                _trace?.Info($"Filtro extra: {filter}");
            }
            catch (Exception ex)
            {
                lock (_widenGate)
                {
                    _capturedClients.Remove(key);
                }

                _trace?.Failure("No se pudo abrir el filtro del flujo.", ex);
            }
        }
    }

    private void FlowLoop(WinDivert handle)
    {
        var buffer = new byte[0xFFFF];
        var addresses = new WinDivertAddress[1];
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var (received, addressCount) = handle.RecvEx(buffer, addresses);
                if (received == 0 || addressCount == 0)
                {
                    continue;
                }

                Handle(handle, buffer.AsSpan(0, (int)received), addresses[0]);
            }
        }
        catch (WinDivertException) when (_stop.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            _trace?.Failure("La captura de un flujo se detuvo.", ex);
        }
    }

    private WinDivert OpenNetwork(string filter)
    {
        var handle = new WinDivert(filter, WinDivert.Layer.Network, _settings.WinDivertPriority, 0)
        {
            QueueLength = 8192,
            QueueTime = 8000,
        };
        return handle;
    }

    private void SocketLoop(WinDivert sockets, CancellationToken cancellationToken)
    {
        var addresses = new WinDivertAddress[1];
        var dummy = new byte[1];

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var (_, addressCount) = sockets.RecvEx(dummy, addresses);
                if (addressCount == 0)
                {
                    continue;
                }

                Observe(addresses[0]);
            }
        }
        catch (WinDivertException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            _trace?.Failure("La captura de la capa SOCKET se detuvo.", ex);
        }
    }

    private void Observe(WinDivertAddress address)
    {
        var socket = address.Socket;
        var protocol = socket.Protocol switch
        {
            6 => TransportProtocol.Tcp,
            17 => TransportProtocol.Udp,
            _ => (TransportProtocol?)null,
        };

        if (protocol is null || socket.LocalPort == 0 || !TryUnmapIPv4(socket.LocalAddr, out var local) || !TryUnmapIPv4(socket.RemoteAddr, out var remote))
        {
            return;
        }

        if (address.Event == WinDivert.Event.SocketClose)
        {
            _sockets.Closed(protocol.Value, local, socket.LocalPort, remote, socket.RemotePort);
            return;
        }

        if (address.Event == WinDivert.Event.SocketConnect)
        {
            _sockets.Connected(protocol.Value, local, socket.LocalPort, remote, socket.RemotePort, (int)socket.ProcessId);
        }
    }

    private static bool TryUnmapIPv4(IPv6Addr address, out IPAddress ip)
    {
        // La capa SOCKET entrega IPv4 como IPv4-mapeada (::ffff:a.b.c.d).
        // ToString() delega en WinDivertHelperFormatIPv6Address, que es quien
        // conoce el orden de bytes que escribe el driver.
        if (!IPAddress.TryParse(address.ToString(), out var parsed))
        {
            ip = IPAddress.None;
            return false;
        }

        if (parsed.IsIPv4MappedToIPv6)
        {
            parsed = parsed.MapToIPv4();
        }

        if (parsed.AddressFamily != AddressFamily.InterNetwork)
        {
            ip = IPAddress.None;
            return false;
        }

        ip = parsed;
        return true;
    }

    private void Send(WinDivert network, ReadOnlySpan<byte> packet, WinDivertAddress address)
    {
        Span<WinDivertAddress> addresses = stackalloc WinDivertAddress[1];
        addresses[0] = address;

        lock (_sendGate)
        {
            _ = network.SendEx(packet, addresses);
        }
    }

    private static void Shutdown(WinDivert? divert)
    {
        if (divert is null)
        {
            return;
        }

        try
        {
            divert.Shutdown();
        }
        catch (WinDivertException)
        {
        }

        divert.Dispose();
    }

}
