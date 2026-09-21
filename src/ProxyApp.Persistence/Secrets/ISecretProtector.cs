using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace ProxyApp.Persistence.Secrets;

/// <summary>
/// Cifra y descifra las contraseñas de proxy. Se inyecta para que los tests no
/// dependan de DPAPI y para poder sustituirlo por un backend de empresa.
/// </summary>
public interface ISecretProtector
{
    /// <summary>Devuelve el secreto cifrado y codificado en Base64.</summary>
    string Protect(string plainText);

    /// <summary>Descifra un valor producido por <see cref="Protect"/>.</summary>
    string Unprotect(string protectedValue);
}

/// <summary>
/// Implementación sobre DPAPI en ámbito de máquina.
/// </summary>
/// <remarks>
/// El ámbito es <see cref="DataProtectionScope.LocalMachine"/> porque quien lee
/// la configuración es el servicio corriendo como LocalSystem, mientras que quien
/// la escribe desde la UI es el usuario interactivo: con ámbito de usuario el
/// servicio no podría descifrar nada. La contrapartida es que cualquier proceso
/// de la máquina podría descifrarlo, y por eso se añade entropía adicional y el
/// fichero se guarda con ACL restringida a Administradores.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class DpapiSecretProtector : ISecretProtector
{
    private static readonly byte[] Entropy = "ProxyApp.OutboundNode.Credentials.v1"u8.ToArray();

    public string Protect(string plainText)
    {
        ArgumentNullException.ThrowIfNull(plainText);

        var cipher = ProtectedData.Protect(
            Encoding.UTF8.GetBytes(plainText),
            Entropy,
            DataProtectionScope.LocalMachine);

        return Convert.ToBase64String(cipher);
    }

    public string Unprotect(string protectedValue)
    {
        ArgumentException.ThrowIfNullOrEmpty(protectedValue);

        var plain = ProtectedData.Unprotect(
            Convert.FromBase64String(protectedValue),
            Entropy,
            DataProtectionScope.LocalMachine);

        return Encoding.UTF8.GetString(plain);
    }
}
