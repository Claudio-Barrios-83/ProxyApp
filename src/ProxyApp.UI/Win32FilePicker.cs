using Microsoft.Win32;

namespace ProxyApp.UI;

public interface IFilePicker
{
    string? PickExecutable();
}

public sealed class Win32FilePicker : IFilePicker
{
    public string? PickExecutable()
    {
        var dialog = new OpenFileDialog
        {
            Filter = "Ejecutables (*.exe)|*.exe",
            CheckFileExists = true,
            Title = "Seleccionar ejecutable",
        };

        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }
}
