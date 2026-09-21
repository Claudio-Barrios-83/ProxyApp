using System.Net;
using System.Runtime.InteropServices;
using ProxyApp.Abstractions.Configuration;
using ProxyApp.Core.Interception;

namespace ProxyApp.Interception;

/// <summary>
/// Plan B del PID: <c>GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)</c>.
/// No cubre UDP, porque esa tabla solo tiene el extremo local.
/// </summary>
public sealed class WindowsConnectionPidResolver : IConnectionPidResolver
{
    private const uint InsufficientBuffer = 122;
    private const int Ipv4 = 2;
    private const int TcpTableOwnerPidAll = 5;

    public bool TryResolve(
        TransportProtocol protocol,
        IPAddress localAddress,
        int localPort,
        IPAddress remoteAddress,
        int remotePort,
        out int processId)
    {
        processId = 0;
        if (protocol != TransportProtocol.Tcp)
        {
            return false;
        }

        var length = 0;
        var probe = GetExtendedTcpTable(IntPtr.Zero, ref length, false, Ipv4, TcpTableOwnerPidAll, 0);
        if (probe != InsufficientBuffer || length <= 0)
        {
            return false;
        }

        var buffer = Marshal.AllocHGlobal(length);
        try
        {
            var result = GetExtendedTcpTable(buffer, ref length, false, Ipv4, TcpTableOwnerPidAll, 0);
            if (result != 0)
            {
                return false;
            }

            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<TcpRowOwnerPid>();
            var cursor = 4;

            for (var index = 0; index < count; index++)
            {
                var row = Marshal.PtrToStructure<TcpRowOwnerPid>(IntPtr.Add(buffer, cursor));
                cursor += rowSize;

                if (HostPort(row.LocalPort) != localPort || HostPort(row.RemotePort) != remotePort)
                {
                    continue;
                }

                if (!AddressOf(row.LocalAddr).Equals(localAddress) || !AddressOf(row.RemoteAddr).Equals(remoteAddress))
                {
                    continue;
                }

                processId = unchecked((int)row.OwningPid);
                return processId > 0;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return false;
    }

    /// <summary>
    /// El puerto viaja en los 16 bits bajos del DWORD, en orden de red.
    /// El byte bajo del DWORD es el byte alto del puerto.
    /// </summary>
    private static int HostPort(uint dword) => ((int)(dword & 0xFF) << 8) | (int)((dword >> 8) & 0xFF);

    private static IPAddress AddressOf(uint networkOrder) => new(BitConverter.GetBytes(networkOrder));

    [StructLayout(LayoutKind.Sequential)]
    private struct TcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr table,
        ref int size,
        bool order,
        uint ipVersion,
        int tableClass,
        uint reserved);
}
