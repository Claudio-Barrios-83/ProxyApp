using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using ProxyApp.Core.Interception;

namespace ProxyApp.Interception;

/// <summary>
/// <c>QueryFullProcessImageName</c> más el SID del token. Corre en el servicio,
/// así que LocalSystem puede abrir procesos de otras sesiones.
/// </summary>
public sealed class WindowsProcessIdentityResolver : IProcessIdentityResolver
{
    private const uint QueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;
    private const int TokenUser = 1;

    private readonly ConcurrentDictionary<int, CacheEntry> _cache = new();
    private readonly TimeSpan _ttl;

    public WindowsProcessIdentityResolver(TimeSpan? ttl = null) => _ttl = ttl ?? TimeSpan.FromSeconds(30);

    public ProcessIdentity? TryResolve(int processId)
    {
        var now = Environment.TickCount64;
        if (_cache.TryGetValue(processId, out var cached) && now < cached.ExpiresAt)
        {
            return cached.Identity;
        }

        var identity = Read(processId);
        _cache[processId] = new CacheEntry(identity, now + (long)_ttl.TotalMilliseconds);
        return identity;
    }

    private static ProcessIdentity? Read(int processId)
    {
        var process = OpenProcess(QueryLimitedInformation, false, processId);
        if (process == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var path = new char[1024];
            var capacity = path.Length;
            if (!QueryFullProcessImageName(process, 0, path, ref capacity) || capacity <= 0)
            {
                return null;
            }

            return new ProcessIdentity(new string(path, 0, capacity), TryGetUserSid(process));
        }
        finally
        {
            _ = CloseHandle(process);
        }
    }

    private static string? TryGetUserSid(IntPtr process)
    {
        if (!OpenProcessToken(process, TokenQuery, out var token))
        {
            return null;
        }

        try
        {
            GetTokenInformation(token, TokenUser, IntPtr.Zero, 0, out var needed);
            var buffer = Marshal.AllocHGlobal(needed);
            try
            {
                if (!GetTokenInformation(token, TokenUser, buffer, needed, out _))
                {
                    return null;
                }

                var user = Marshal.PtrToStructure<SidAndAttributes>(buffer);
                if (!ConvertSidToStringSid(user.Sid, out var sidText) || sidText == IntPtr.Zero)
                {
                    return null;
                }

                try
                {
                    return Marshal.PtrToStringUni(sidText);
                }
                finally
                {
                    _ = LocalFree(sidText);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            _ = CloseHandle(token);
        }
    }

    private readonly record struct CacheEntry(ProcessIdentity? Identity, long ExpiresAt);

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr process, int flags, char[] name, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr token,
        int informationClass,
        IntPtr buffer,
        int length,
        out int returnLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr sidString);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
