namespace ProxyApp.Interception;

/// <summary>Salida de diagnóstico del bucle de captura. La UI puede engancharla al log.</summary>
public interface IFilterTrace
{
    void Info(string message);

    void Failure(string message, Exception? exception = null);
}
