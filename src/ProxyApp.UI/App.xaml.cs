using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace ProxyApp.UI;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;
        base.OnStartup(e);

        var window = new MainWindow
        {
            DataContext = new MainViewModel(new Win32FilePicker()),
        };
        MainWindow = window;
        window.Show();
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        WriteCrash(e.Exception);
        MessageBox.Show(e.Exception.Message, "ProxyApp", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }

    private static void OnDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception exception)
        {
            WriteCrash(exception);
        }
    }

    private static void WriteCrash(Exception exception)
    {
        try
        {
            var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ProxyApp");
            Directory.CreateDirectory(directory);
            File.AppendAllText(Path.Combine(directory, "crash.log"), exception + Environment.NewLine + Environment.NewLine);
        }
        catch (IOException)
        {
        }
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
