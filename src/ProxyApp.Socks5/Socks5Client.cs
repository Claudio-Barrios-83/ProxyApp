using System.Globalization;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ProxyApp.Socks5;

/// <summary>Método de autenticación SOCKS5 elegido en el saludo (RFC 1928 §3).</summary>
public enum Socks5AuthMethod : byte
{
    NoAuthentication = 0x00,
    UsernamePassword = 0x02,
    NoAcceptableMethod = 0xFF,
}

/// <summary>Código REP de la respuesta CONNECT (RFC 1928 §6).</summary>
public enum Socks5Reply : byte
{
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    NotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

/// <summary>Por qué falló el intento. Sirve para decidir si tiene sentido reintentar.</summary>
public enum Socks5FailureKind
{
    /// <summary>El proxy no contestó dentro del plazo. Reintentable.</summary>
    Timeout,

    /// <summary>No se pudo abrir el TCP contra el proxy. Reintentable.</summary>
    ProxyUnreachable,

    /// <summary>El proxy rechazó el método o la contraseña. No reintentar igual.</summary>
    AuthenticationRejected,

    /// <summary>El destino contestó con REP 0x05. No reintentar el mismo destino.</summary>
    ConnectionRefused,

    /// <summary>Cualquier otro REP distinto de éxito.</summary>
    ProxyRejected,

    /// <summary>El proxy cerró a mitad del saludo. Reintentable.</summary>
    UnexpectedClose,

    /// <summary>Versión, ATYP o longitud imposibles.</summary>
    ProtocolViolation,

    /// <summary>Corte de la conexión ya establecida, durante el reenvío.</summary>
    Transport,
}

/// <summary>Credenciales en claro. Quien llama descifra DPAPI antes de construirlas.</summary>
public sealed record Socks5Credentials
{
    public Socks5Credentials(string username, string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);
        ArgumentNullException.ThrowIfNull(password);
        Username = username;
        Password = password;
    }

    public string Username { get; }

    public string Password { get; }
}

/// <summary>Plazos y reintentos del saludo. El reenvío de datos ya establecido no se repite.</summary>
public sealed record Socks5ClientOptions
{
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(10);

    public TimeSpan HandshakeTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Reintentos del TCP y del saludo, antes de que circule un byte de la aplicación.
    /// Reenviar un túnel ya a medias duplicaría datos.
    /// </summary>
    public int MaxHandshakeAttempts { get; init; } = 2;

    public TimeSpan RetryDelay { get; init; } = TimeSpan.FromMilliseconds(200);

    public void Validate()
    {
        if (ConnectTimeout <= TimeSpan.Zero || HandshakeTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(ConnectTimeout), "Los plazos tienen que ser positivos.");
        }

        if (MaxHandshakeAttempts < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(MaxHandshakeAttempts));
        }
    }
}

/// <summary>Fallo del protocolo o del transporte SOCKS5.</summary>
public sealed class Socks5Exception : IOException
{
    public Socks5Exception(Socks5FailureKind kind, string message, Socks5Reply? reply = null, Exception? inner = null)
        : base(message, inner)
    {
        Kind = kind;
        Reply = reply;
    }

    public Socks5FailureKind Kind { get; }

    public Socks5Reply? Reply { get; }

    /// <summary>Solo el saludo se reintenta. Un REP definitivo o una contraseña mala, no.</summary>
    public bool CanRetryHandshake => Kind is Socks5FailureKind.Timeout
        or Socks5FailureKind.ProxyUnreachable
        or Socks5FailureKind.UnexpectedClose;
}

/// <summary>Octetos movidos en cada sentido y si algún lado cortó sin un FIN limpio.</summary>
public readonly record struct Socks5RelayResult(long BytesToProxy, long BytesFromProxy, bool AbruptClose);

/// <summary>Avance del reenvío, para refrescar contadores sin esperar al cierre.</summary>
public readonly record struct Socks5RelaySnapshot(long BytesToProxy, long BytesFromProxy);

/// <summary>
/// Túnel ya autenticado. El stream es la conexión con el proxy, lista para datos de aplicación.
/// </summary>
public sealed class Socks5Connection : IAsyncDisposable
{
    private readonly TcpClient _client;
    private int _disposed;

    internal Socks5Connection(TcpClient client, Stream stream, IPEndPoint boundEndpoint)
    {
        _client = client;
        Stream = stream;
        BoundEndpoint = boundEndpoint;
    }

    public Stream Stream { get; }

    /// <summary>BND.ADDR y BND.PORT que devolvió el proxy. Muchos servidores mandan 0.0.0.0:0.</summary>
    public IPEndPoint BoundEndpoint { get; }

    public Task<Socks5RelayResult> RelayAsync(Stream application, CancellationToken cancellationToken = default) =>
        Socks5Client.RelayAsync(application, Stream, cancellationToken);

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await Stream.DisposeAsync().ConfigureAwait(false);
        _client.Dispose();
    }
}

/// <summary>
/// Cliente SOCKS5 (RFC 1928) con autenticación sin credenciales o usuario/contraseña (RFC 1929).
/// El destino se envía como IPv4 o como nombre: el proxy resuelve el DNS, no esta máquina.
/// </summary>
public sealed class Socks5Client
{
    private const byte Version = 0x05;
    private const byte AuthVersion = 0x01;
    private const byte CommandConnect = 0x01;
    private const byte AddressIPv4 = 0x01;
    private const byte AddressDomain = 0x03;
    private const byte AddressIPv6 = 0x04;

    private readonly string _proxyHost;
    private readonly int _proxyPort;
    private readonly Socks5Credentials? _credentials;
    private readonly Socks5ClientOptions _options;

    public Socks5Client(string proxyHost, int proxyPort, Socks5Credentials? credentials = null, Socks5ClientOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(proxyHost);
        if (proxyPort is <= 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(proxyPort));
        }

        _options = options ?? new Socks5ClientOptions();
        _options.Validate();
        _proxyHost = proxyHost;
        _proxyPort = proxyPort;
        _credentials = credentials;
    }

    /// <summary>
    /// Abre el TCP contra el proxy, negocia la autenticación y ejecuta CONNECT.
    /// Un nombre se manda como ATYP 0x03, sin <c>Dns.GetHostAddresses</c> local.
    /// </summary>
    public async Task<Socks5Connection> ConnectAsync(string targetHost, int targetPort, CancellationToken cancellationToken = default)
    {
        ValidateTarget(targetHost, targetPort);

        Socks5Exception? last = null;
        for (var attempt = 1; attempt <= _options.MaxHandshakeAttempts; attempt++)
        {
            try
            {
                return await ConnectOnceAsync(targetHost, targetPort, cancellationToken).ConfigureAwait(false);
            }
            catch (Socks5Exception ex) when (ex.CanRetryHandshake && attempt < _options.MaxHandshakeAttempts)
            {
                last = ex;
                await Task.Delay(_options.RetryDelay, cancellationToken).ConfigureAwait(false);
            }
        }

        throw last ?? new Socks5Exception(Socks5FailureKind.Transport, "No se pudo abrir el túnel SOCKS5.");
    }

    /// <summary>
    /// Copia en los dos sentidos hasta que ambos reciben fin de datos.
    /// Un reset se registra en <see cref="Socks5RelayResult.AbruptClose"/> y no se relanza:
    /// el otro sentido tiene que poder terminar de vaciar lo que ya tenía.
    /// </summary>
    public static Task<Socks5RelayResult> RelayAsync(Stream application, Stream tunnel, CancellationToken cancellationToken = default) =>
        RelayCoreAsync(application, tunnel, progress: null, cancellationToken);

    public static Task<Socks5RelayResult> RelayAsync(
        Stream application,
        Stream tunnel,
        IProgress<Socks5RelaySnapshot>? progress,
        CancellationToken cancellationToken = default) =>
        RelayCoreAsync(application, tunnel, progress, cancellationToken);

    private static async Task<Socks5RelayResult> RelayCoreAsync(
        Stream application,
        Stream tunnel,
        IProgress<Socks5RelaySnapshot>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        ArgumentNullException.ThrowIfNull(tunnel);

        var meter = progress is null ? null : new RelayMeter(progress);
        var toProxy = PumpAsync(application, tunnel, cancellationToken, meter, upload: true);
        var fromProxy = PumpAsync(tunnel, application, cancellationToken, meter, upload: false);
        await Task.WhenAll(toProxy, fromProxy).ConfigureAwait(false);
        meter?.ReportNow();

        return new Socks5RelayResult(toProxy.Result.Bytes, fromProxy.Result.Bytes, toProxy.Result.Reset || fromProxy.Result.Reset);
    }

    private async Task<Socks5Connection> ConnectOnceAsync(string targetHost, int targetPort, CancellationToken cancellationToken)
    {
        var tcp = new TcpClient { NoDelay = true };
        try
        {
            await ConnectProxyAsync(tcp, cancellationToken).ConfigureAwait(false);
            var stream = tcp.GetStream();
            var bound = await HandshakeAsync(stream, targetHost, targetPort, cancellationToken).ConfigureAwait(false);
            return new Socks5Connection(tcp, stream, bound);
        }
        catch (Exception ex) when (ex is not Socks5Exception)
        {
            tcp.Dispose();
            throw WrapTransport(ex, cancellationToken);
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    private async Task ConnectProxyAsync(TcpClient tcp, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.ConnectTimeout);
        try
        {
            await tcp.ConnectAsync(_proxyHost, _proxyPort, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new Socks5Exception(Socks5FailureKind.Timeout, $"El proxy {_proxyHost}:{_proxyPort} no aceptó la conexión a tiempo.");
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
        {
            throw new Socks5Exception(Socks5FailureKind.ProxyUnreachable, $"El proxy {_proxyHost}:{_proxyPort} rechazó la conexión.", inner: ex);
        }
        catch (SocketException ex)
        {
            throw new Socks5Exception(Socks5FailureKind.ProxyUnreachable, $"No se pudo contactar al proxy {_proxyHost}:{_proxyPort}.", inner: ex);
        }
    }

    private async Task<IPEndPoint> HandshakeAsync(NetworkStream stream, string targetHost, int targetPort, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.HandshakeTimeout);
        var token = timeout.Token;

        try
        {
            await NegotiateAuthAsync(stream, token).ConfigureAwait(false);
            return await SendConnectAsync(stream, targetHost, targetPort, token).ConfigureAwait(false);
        }
        catch (Socks5Exception)
        {
            throw;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new Socks5Exception(Socks5FailureKind.Timeout, "El proxy no completó el saludo SOCKS5 a tiempo.");
        }
        catch (Exception ex) when (ex is EndOfStreamException or IOException or SocketException)
        {
            throw new Socks5Exception(Socks5FailureKind.UnexpectedClose, "El proxy cerró durante el saludo.", inner: ex);
        }
    }

    private async Task NegotiateAuthAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        byte[] greeting = _credentials is null
            ? [Version, 0x01, (byte)Socks5AuthMethod.NoAuthentication]
            : [Version, 0x01, (byte)Socks5AuthMethod.UsernamePassword];

        await stream.WriteAsync(greeting, cancellationToken).ConfigureAwait(false);

        var choice = new byte[2];
        await stream.ReadExactlyAsync(choice, cancellationToken).ConfigureAwait(false);
        if (choice[0] != Version)
        {
            throw new Socks5Exception(Socks5FailureKind.ProtocolViolation, $"Versión SOCKS inesperada: 0x{choice[0]:X2}.");
        }

        var method = (Socks5AuthMethod)choice[1];
        if (method == Socks5AuthMethod.NoAcceptableMethod)
        {
            throw new Socks5Exception(Socks5FailureKind.AuthenticationRejected, "El proxy no acepta el método de autenticación ofrecido.");
        }

        if (_credentials is null)
        {
            if (method != Socks5AuthMethod.NoAuthentication)
            {
                throw new Socks5Exception(Socks5FailureKind.ProtocolViolation, $"El proxy eligió el método 0x{choice[1]:X2} sin que se ofreciera.");
            }

            return;
        }

        if (method != Socks5AuthMethod.UsernamePassword)
        {
            throw new Socks5Exception(Socks5FailureKind.ProtocolViolation, $"El proxy eligió el método 0x{choice[1]:X2} en lugar de usuario/contraseña.");
        }

        await WriteUserPassAsync(stream, _credentials, cancellationToken).ConfigureAwait(false);

        var authReply = new byte[2];
        await stream.ReadExactlyAsync(authReply, cancellationToken).ConfigureAwait(false);
        if (authReply[0] != AuthVersion || authReply[1] != 0x00)
        {
            throw new Socks5Exception(Socks5FailureKind.AuthenticationRejected, "El proxy rechazó el usuario o la contraseña.");
        }
    }

    private static async Task WriteUserPassAsync(NetworkStream stream, Socks5Credentials credentials, CancellationToken cancellationToken)
    {
        var user = Encoding.UTF8.GetBytes(credentials.Username);
        var password = Encoding.UTF8.GetBytes(credentials.Password);
        if (user.Length is 0 or > 255 || password.Length > 255)
        {
            throw new Socks5Exception(Socks5FailureKind.ProtocolViolation, "Usuario o contraseña fuera del límite de 255 octetos.");
        }

        var payload = new byte[3 + user.Length + password.Length];
        payload[0] = AuthVersion;
        payload[1] = (byte)user.Length;
        user.CopyTo(payload.AsSpan(2));
        payload[2 + user.Length] = (byte)password.Length;
        password.CopyTo(payload.AsSpan(3 + user.Length));
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<IPEndPoint> SendConnectAsync(NetworkStream stream, string targetHost, int targetPort, CancellationToken cancellationToken)
    {
        var request = BuildConnectRequest(targetHost, targetPort);
        await stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);

        var header = new byte[4];
        await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
        if (header[0] != Version)
        {
            throw new Socks5Exception(Socks5FailureKind.ProtocolViolation, $"Versión inesperada en la respuesta CONNECT: 0x{header[0]:X2}.");
        }

        var reply = (Socks5Reply)header[1];
        var (address, port) = await ReadBoundEndpointAsync(stream, header[3], cancellationToken).ConfigureAwait(false);
        if (reply != Socks5Reply.Succeeded)
        {
            var kind = reply == Socks5Reply.ConnectionRefused
                ? Socks5FailureKind.ConnectionRefused
                : Socks5FailureKind.ProxyRejected;
            throw new Socks5Exception(kind, $"CONNECT rechazado por el proxy ({reply}).", reply);
        }

        return new IPEndPoint(address, port);
    }

    private static byte[] BuildConnectRequest(string targetHost, int targetPort)
    {
        var portHi = (byte)(targetPort >> 8);
        var portLo = (byte)targetPort;

        if (IPAddress.TryParse(targetHost, out var ip))
        {
            if (ip.IsIPv4MappedToIPv6)
            {
                ip = ip.MapToIPv4();
            }

            var raw = ip.GetAddressBytes();
            var atyp = ip.AddressFamily == AddressFamily.InterNetwork ? AddressIPv4 : AddressIPv6;
            var request = new byte[4 + raw.Length + 2];
            request[0] = Version;
            request[1] = CommandConnect;
            request[3] = atyp;
            raw.CopyTo(request.AsSpan(4));
            request[^2] = portHi;
            request[^1] = portLo;
            return request;
        }

        string ascii;
        try
        {
            ascii = new IdnMapping().GetAscii(targetHost);
        }
        catch (ArgumentException ex)
        {
            throw new Socks5Exception(Socks5FailureKind.ProtocolViolation, $"El nombre '{targetHost}' no es un dominio válido.", inner: ex);
        }

        if (ascii.Length is 0 or > 255)
        {
            throw new Socks5Exception(Socks5FailureKind.ProtocolViolation, "El nombre de dominio supera los 255 octetos.");
        }

        var domain = Encoding.ASCII.GetBytes(ascii);
        var frame = new byte[5 + domain.Length + 2];
        frame[0] = Version;
        frame[1] = CommandConnect;
        frame[3] = AddressDomain;
        frame[4] = (byte)domain.Length;
        domain.CopyTo(frame.AsSpan(5));
        frame[^2] = portHi;
        frame[^1] = portLo;
        return frame;
    }

    private static async Task<(IPAddress Address, int Port)> ReadBoundEndpointAsync(NetworkStream stream, byte addressType, CancellationToken cancellationToken)
    {
        int length = addressType switch
        {
            AddressIPv4 => 4,
            AddressIPv6 => 16,
            AddressDomain => -1,
            _ => throw new Socks5Exception(Socks5FailureKind.ProtocolViolation, $"ATYP de respuesta no soportado: 0x{addressType:X2}."),
        };

        if (length < 0)
        {
            var lenBuf = new byte[1];
            await stream.ReadExactlyAsync(lenBuf, cancellationToken).ConfigureAwait(false);
            length = lenBuf[0];
        }

        var body = new byte[length + 2];
        await stream.ReadExactlyAsync(body, cancellationToken).ConfigureAwait(false);
        var port = (body[^2] << 8) | body[^1];

        if (addressType == AddressDomain)
        {
            // El nombre enlazado no es una dirección de socket. Se conserva como 0.0.0.0
            // y el puerto, que es lo único que el llamador puede usar.
            return (IPAddress.Any, port);
        }

        return (new IPAddress(body.AsSpan(..length)), port);
    }

    private static async Task<PumpResult> PumpAsync(
        Stream source,
        Stream destination,
        CancellationToken cancellationToken,
        RelayMeter? meter = null,
        bool upload = false)
    {
        var reader = PipeReader.Create(source, new StreamPipeReaderOptions(bufferSize: 65_536, leaveOpen: true));
        var writer = PipeWriter.Create(destination, new StreamPipeWriterOptions(leaveOpen: true));
        long total = 0;
        var reset = false;

        try
        {
            while (true)
            {
                var read = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                var buffer = read.Buffer;
                var destinationClosed = false;
                if (buffer.Length > 0)
                {
                    foreach (var segment in buffer)
                    {
                        var memory = writer.GetMemory(segment.Length);
                        segment.Span.CopyTo(memory.Span);
                        writer.Advance(segment.Length);
                    }

                    total += buffer.Length;
                    meter?.Add(upload, buffer.Length);
                    var flushed = await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                    destinationClosed = flushed.IsCompleted;
                }

                // AdvanceTo es obligatorio antes de Complete, también cuando el destino ya cerró.
                reader.AdvanceTo(buffer.End);
                if (destinationClosed || read.IsCompleted || read.IsCanceled)
                {
                    break;
                }
            }
        }
        catch (Exception ex) when (IsAbruptClose(ex))
        {
            reset = true;
        }
        finally
        {
            await reader.CompleteAsync().ConfigureAwait(false);
            await writer.CompleteAsync().ConfigureAwait(false);
            ShutdownSend(destination);
        }

        return new PumpResult(total, reset);
    }

    private static void ShutdownSend(Stream stream)
    {
        if (stream is not NetworkStream network)
        {
            return;
        }

        try
        {
            network.Socket.Shutdown(SocketShutdown.Send);
        }
        catch (SocketException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private static bool IsAbruptClose(Exception exception) =>
        exception is IOException or SocketException or ObjectDisposedException;

    private static Exception WrapTransport(Exception exception, CancellationToken cancellationToken)
    {
        if (exception is OperationCanceledException && cancellationToken.IsCancellationRequested)
        {
            return exception;
        }

        if (exception is OperationCanceledException)
        {
            return new Socks5Exception(Socks5FailureKind.Timeout, "Tiempo de espera agotado contra el proxy.", inner: exception);
        }

        return new Socks5Exception(Socks5FailureKind.Transport, "Fallo de transporte contra el proxy.", inner: exception);
    }

    private static void ValidateTarget(string targetHost, int targetPort)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetHost);
        if (targetPort is <= 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(targetPort));
        }
    }

    private readonly record struct PumpResult(long Bytes, bool Reset);

    private sealed class RelayMeter
    {
        private readonly IProgress<Socks5RelaySnapshot> _progress;
        private long _up;
        private long _down;
        private long _lastReport;

        public RelayMeter(IProgress<Socks5RelaySnapshot> progress) => _progress = progress;

        public void Add(bool upload, long bytes)
        {
            if (upload)
            {
                Interlocked.Add(ref _up, bytes);
            }
            else
            {
                Interlocked.Add(ref _down, bytes);
            }

            var now = Environment.TickCount64;
            var last = Volatile.Read(ref _lastReport);
            if (now - last < 80)
            {
                return;
            }

            if (Interlocked.CompareExchange(ref _lastReport, now, last) == last)
            {
                ReportNow();
            }
        }

        public void ReportNow() =>
            _progress.Report(new Socks5RelaySnapshot(Volatile.Read(ref _up), Volatile.Read(ref _down)));
    }
}
