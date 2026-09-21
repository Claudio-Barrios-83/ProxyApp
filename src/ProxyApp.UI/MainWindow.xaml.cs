using System.ComponentModel;
using System.Drawing;
using System.IO;
using System.Windows;

namespace ProxyApp.UI;

public partial class MainWindow : Window
{
    private bool _forceClose;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += (_, _) => TrayIcon.Icon = LoadTrayIcon();
    }

    private static Icon LoadTrayIcon()
    {
        var resource = Application.GetResourceStream(new Uri("pack://application:,,,/Assets/tray.ico", UriKind.Absolute));
        if (resource is null)
        {
            throw new FileNotFoundException("No está el icono de la bandeja.");
        }

        using var copy = new MemoryStream();
        resource.Stream.CopyTo(copy);
        copy.Position = 0;
        return new Icon(copy);
    }

    public void BringToFront()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    public void CloseForReal()
    {
        _forceClose = true;
        TrayIcon.Dispose();
        Close();
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!_forceClose)
        {
            e.Cancel = true;
            Hide();
            return;
        }

        base.OnClosing(e);
    }

    private void TrayIcon_OnDoubleClick(object sender, RoutedEventArgs e) => BringToFront();

    private void Activate_OnClick(object sender, RoutedEventArgs e) => Model?.EnableCommand.Execute(null);

    private void Deactivate_OnClick(object sender, RoutedEventArgs e) => Model?.DisableCommand.Execute(null);

    private void Open_OnClick(object sender, RoutedEventArgs e) => BringToFront();

    private void Exit_OnClick(object sender, RoutedEventArgs e)
    {
        Model?.Shutdown();
        CloseForReal();
        Application.Current.Shutdown();
    }

    private MainViewModel? Model => DataContext as MainViewModel;
}
