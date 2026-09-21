using System.Windows;

namespace ProxyApp.UI;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var window = new MainWindow
        {
            DataContext = new MainViewModel(new Win32FilePicker()),
        };
        MainWindow = window;
        window.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (MainWindow?.DataContext is MainViewModel viewModel)
        {
            viewModel.Shutdown();
        }

        base.OnExit(e);
    }
}
