using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Net;
using System.Security.Principal;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ProxyApp.Abstractions.Configuration;
using ProxyApp.Abstractions.Routing;
using ProxyApp.Core.Interception;
using ProxyApp.Core.Rules;
using ProxyApp.Interception;
using ProxyApp.Socks5;

namespace ProxyApp.UI;

public partial class MainViewModel : ObservableObject
{
    private const int MaxRows = 400;

    private readonly RoutingRuleEngine _engine = new();
    private readonly IFilePicker _files;
    private readonly string _rulesPath;
    private readonly SynchronizationContext? _ui;
    private readonly Dictionary<Guid, TrafficRow> _rows = [];

    private CancellationTokenSource? _session;
    private ProcessNetworkFilter? _filter;
    private TunnelBroker? _broker;
    private Guid? _editingId;
    private int _generation;
    private bool _suppressToggle;

    public MainViewModel(IFilePicker files, string? rulesPath = null)
    {
        _files = files;
        _rulesPath = rulesPath ?? DefaultRulesPath;
        _ui = SynchronizationContext.Current;
        RefreshExits();
        LoadRules();
    }

    public ObservableCollection<ExitChoice> Exits { get; } = [];

    public ObservableCollection<TrafficRow> Traffic { get; } = [];

    public ObservableCollection<Rule> Rules { get; } = [];

    public static string DefaultRulesPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ProxyApp", "rules.json");

    [ObservableProperty]
    private bool _isEngineEnabled;

    [ObservableProperty]
    private string _statusMessage = "Motor detenido.";

    [ObservableProperty]
    private Rule? _selectedRule;

    [ObservableProperty]
    private string _executablePath = "";

    [ObservableProperty]
    private string _processPattern = "";

    [ObservableProperty]
    private string _proxyHost = "";

    [ObservableProperty]
    private string _proxyPort = "";

    [ObservableProperty]
    private bool _ruleEnabled = true;

    [ObservableProperty]
    private bool _bypassLocal = true;

    [ObservableProperty]
    private ExitChoice? _selectedExit;

    [ObservableProperty]
    private bool _isSocksExit = true;

    partial void OnSelectedExitChanged(ExitChoice? value) => IsSocksExit = value is null || value.IsSocks;

    public void Shutdown()
    {
        _generation++;
        StopCore();
    }

    partial void OnIsEngineEnabledChanged(bool value)
    {
        if (_suppressToggle)
        {
            return;
        }

        if (value)
        {
            Start();
            return;
        }

        _generation++;
        StopCore();
        StatusMessage = "Motor detenido.";
    }

    partial void OnSelectedRuleChanged(Rule? value)
    {
        if (value is null)
        {
            return;
        }

        _editingId = value.RuleId;
        ExecutablePath = "";
        ProcessPattern = value.ProcessName;
        ProxyHost = value.TargetProxy.Host ?? "";
        ProxyPort = value.TargetProxy.Port == 0 ? "" : value.TargetProxy.Port.ToString(CultureInfo.InvariantCulture);
        SelectedExit = value.TargetProxy.Type == ProxyType.Adapter
            ? Exits.FirstOrDefault(item => !item.IsSocks && string.Equals(item.InterfaceName, value.TargetProxy.Host, StringComparison.OrdinalIgnoreCase))
              ?? EnsureExit(value.TargetProxy.Host ?? "")
            : Exits.FirstOrDefault(item => item.IsSocks);
        RuleEnabled = value.IsEnabled;
        BypassLocal = value.BypassLocalNetwork;
    }

    [RelayCommand]
    private void Enable() => IsEngineEnabled = true;

    [RelayCommand]
    private void Disable() => IsEngineEnabled = false;

    [RelayCommand]
#pragma warning disable CA1822 // El comando tiene que ser de instancia para enlazarlo desde el menú.
    private void Open()
    {
        if (Application.Current?.MainWindow is MainWindow window)
        {
            window.BringToFront();
        }
    }
#pragma warning restore CA1822

    [RelayCommand]
    private void Exit()
    {
        Shutdown();
        if (Application.Current?.MainWindow is MainWindow window)
        {
            window.CloseForReal();
        }

        Application.Current?.Shutdown();
    }

    [RelayCommand]
    private void BrowseExecutable()
    {
        var path = _files.PickExecutable();
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        ExecutablePath = path;
        ProcessPattern = FileName(path);
    }

    [RelayCommand]
    private void NewRule()
    {
        _editingId = null;
        SelectedRule = null;
        ExecutablePath = "";
        ProcessPattern = "";
        ProxyHost = "";
        ProxyPort = "";
        SelectedExit = Exits.FirstOrDefault(item => !item.IsSocks) ?? Exits.FirstOrDefault();
        RuleEnabled = true;
        BypassLocal = true;
        StatusMessage = "Nueva regla.";
    }

    [RelayCommand]
    private void SaveRule()
    {
        var pattern = ProcessPattern.Trim();
        if (pattern.Length == 0)
        {
            StatusMessage = "Selecciona un ejecutable.";
            return;
        }

        Proxy proxy;
        if (SelectedExit is { IsSocks: false } vpn)
        {
            proxy = new Proxy
            {
                Type = ProxyType.Adapter,
                Host = vpn.InterfaceName,
                Port = 0,
            };
        }
        else
        {
            if (!int.TryParse(ProxyPort, NumberStyles.None, CultureInfo.InvariantCulture, out var port))
            {
                StatusMessage = "El puerto del proxy tiene que estar entre 1 y 65535.";
                return;
            }

            proxy = new Proxy
            {
                Type = ProxyType.Socks5,
                Host = ProxyHost.Trim(),
                Port = port,
            };
        }
        var errors = proxy.Validate();
        if (errors.Count > 0)
        {
            StatusMessage = errors[0];
            return;
        }

        var rule = new Rule
        {
            RuleId = _editingId ?? Guid.NewGuid(),
            ProcessName = pattern,
            TargetProxy = proxy,
            IsEnabled = RuleEnabled,
            BypassLocalNetwork = BypassLocal,
        };

        var index = IndexOf(rule.RuleId);
        if (index >= 0)
        {
            Rules[index] = rule;
        }
        else
        {
            Rules.Add(rule);
        }

        _editingId = rule.RuleId;
        if (!Persist())
        {
            return;
        }

        SelectedRule = rule;
        StatusMessage = "Regla guardada.";
    }

    [RelayCommand]
    private void DeleteRule()
    {
        if (SelectedRule is null)
        {
            return;
        }

        var index = IndexOf(SelectedRule.RuleId);
        if (index >= 0)
        {
            Rules.RemoveAt(index);
        }

        _editingId = null;
        SelectedRule = null;
        if (Persist())
        {
            StatusMessage = "Regla eliminada.";
        }
    }

    private void Start()
    {
        if (!IsAdministrator())
        {
            FailStart(_generation, new InvalidOperationException("Hay que ejecutar ProxyApp como administrador para cargar el filtro de red."));
            return;
        }

        var directory = AppContext.BaseDirectory;
        if (!File.Exists(Path.Combine(directory, "WinDivert.dll")) || !File.Exists(Path.Combine(directory, "WinDivert64.sys")))
        {
            FailStart(_generation, new FileNotFoundException("Faltan WinDivert.dll y WinDivert64.sys junto a ProxyApp.exe."));
            return;
        }

        StatusMessage = "Arrancando motor…";
        var generation = ++_generation;
        StopCore();

        var session = new CancellationTokenSource();
        TunnelBroker? broker = null;
        ProcessNetworkFilter? filter = null;
        try
        {
            broker = new TunnelBroker(WindowsNetworkInterfaces.TryGetIndex, WindowsNetworkInterfaces.Bind);
            broker.TrafficChanged += OnTraffic;
            filter = new ProcessNetworkFilter(
                _engine,
                broker.ListenEndpoint,
                new WindowsProcessIdentityResolver(),
                new WindowsConnectionPidResolver(),
                trace: new UiTrace(message => Post(() => StatusMessage = message)));

            _session = session;
            _broker = broker;
            _filter = filter;
            StatusMessage = "Motor en marcha.";

            var token = session.Token;
            _ = Task.Run(() => broker.RunAsync(Resolve, token));
            _ = Task.Run(() =>
            {
                try
                {
                    filter.Run(token);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    Post(() => FailStart(generation, ex));
                }
            });
        }
        catch (Exception ex)
        {
            session.Dispose();
            if (broker is not null)
            {
                broker.TrafficChanged -= OnTraffic;
                broker.Dispose();
            }

            filter?.Dispose();
            FailStart(generation, ex);
        }
    }

    private InterceptedFlow? Resolve(IPEndPoint endpoint) =>
        _filter is not null && _filter.TryGetSession(endpoint, TransportProtocol.Tcp, out var flow) ? flow : null;

    private void FailStart(int generation, Exception exception)
    {
        if (generation != _generation)
        {
            return;
        }

        _generation++;
        StopCore();
        _suppressToggle = true;
        IsEngineEnabled = false;
        _suppressToggle = false;
        StatusMessage = "No se pudo activar el motor. " + exception.Message;
    }

    private void StopCore()
    {
        _session?.Cancel();
        _session?.Dispose();
        _session = null;

        if (_broker is not null)
        {
            _broker.TrafficChanged -= OnTraffic;
            _broker.Dispose();
            _broker = null;
        }

        _filter?.Dispose();
        _filter = null;
    }

    private void OnTraffic(TunnelTrafficUpdate update)
    {
        Post(() =>
        {
            if (!_rows.TryGetValue(update.Id, out var row))
            {
                row = new TrafficRow
                {
                    Id = update.Id,
                    Time = update.Time.LocalDateTime.ToString("HH:mm:ss", CultureInfo.CurrentCulture),
                    Process = update.Process,
                    OriginalDestination = update.OriginalDestination,
                };
                _rows.Add(update.Id, row);
                Traffic.Insert(0, row);
                while (Traffic.Count > MaxRows)
                {
                    var last = Traffic[^1];
                    Traffic.RemoveAt(Traffic.Count - 1);
                    _rows.Remove(last.Id);
                }
            }

            row.Proxy = update.Proxy;
            row.Status = update.Status;
            row.Volume = string.Create(CultureInfo.CurrentCulture, $"{update.SentBytes / 1024d:0.0} / {update.ReceivedBytes / 1024d:0.0}");
        });
    }

    [RelayCommand]
    private void RefreshExits()
    {
        var previous = SelectedExit?.InterfaceName;
        var wasSocks = SelectedExit?.IsSocks ?? true;
        Exits.Clear();
        Exits.Add(ExitChoice.Socks());
        foreach (var adapter in WindowsNetworkInterfaces.ListVpn())
        {
            Exits.Add(new ExitChoice
            {
                Label = adapter.Label,
                InterfaceName = adapter.Name,
                IsSocks = false,
            });
        }

        SelectedExit = wasSocks
            ? Exits[0]
            : Exits.FirstOrDefault(item => string.Equals(item.InterfaceName, previous, StringComparison.OrdinalIgnoreCase))
              ?? Exits.FirstOrDefault(item => !item.IsSocks)
              ?? Exits[0];
    }

    private ExitChoice EnsureExit(string interfaceName)
    {
        var existing = Exits.FirstOrDefault(item => string.Equals(item.InterfaceName, interfaceName, StringComparison.OrdinalIgnoreCase));
        if (existing is not null)
        {
            return existing;
        }

        var created = new ExitChoice
        {
            Label = interfaceName + " (no está conectada)",
            InterfaceName = interfaceName,
            IsSocks = false,
        };
        Exits.Add(created);
        return created;
    }

    private void LoadRules()
    {
        if (!File.Exists(_rulesPath))
        {
            return;
        }

        try
        {
            _engine.LoadRulesFromJson(_rulesPath);
            foreach (var rule in _engine.Rules)
            {
                Rules.Add(rule);
            }
        }
        catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException or InvalidOperationException)
        {
            StatusMessage = "No se pudieron cargar las reglas. " + ex.Message;
        }
    }

    private bool Persist()
    {
        try
        {
            _engine.ReplaceRules(Rules.ToArray());
            var directory = Path.GetDirectoryName(_rulesPath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            _engine.SaveRulesToJson(_rulesPath);
            return true;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or ArgumentException)
        {
            StatusMessage = "No se pudieron guardar las reglas. " + ex.Message;
            return false;
        }
    }

    private int IndexOf(Guid ruleId)
    {
        for (var i = 0; i < Rules.Count; i++)
        {
            if (Rules[i].RuleId == ruleId)
            {
                return i;
            }
        }

        return -1;
    }

    private void Post(Action action)
    {
        if (_ui is null || SynchronizationContext.Current == _ui)
        {
            action();
            return;
        }

        _ui.Post(_ => action(), null);
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static string FileName(string path)
    {
        var slash = path.LastIndexOfAny(['\\', '/']);
        return slash < 0 ? path : path[(slash + 1)..];
    }

    private sealed class UiTrace(Action<string> failure) : IFilterTrace
    {
        public void Info(string message)
        {
        }

        public void Failure(string message, Exception? exception = null) => failure(message);
    }
}

public sealed class ExitChoice
{
    public static ExitChoice Socks() => new()
    {
        Label = "Proxy SOCKS5",
        InterfaceName = "",
        IsSocks = true,
    };

    public required string Label { get; init; }

    public required string InterfaceName { get; init; }

    public bool IsSocks { get; init; }
}
