using CommunityToolkit.Mvvm.ComponentModel;

namespace ProxyApp.UI;

public partial class TrafficRow : ObservableObject
{
    public Guid Id { get; init; }

    public string Time { get; init; } = "";

    public string Process { get; init; } = "";

    public string OriginalDestination { get; init; } = "";

    [ObservableProperty]
    private string _proxy = "";

    [ObservableProperty]
    private string _status = "";

    [ObservableProperty]
    private string _volume = "0.0 / 0.0";
}
