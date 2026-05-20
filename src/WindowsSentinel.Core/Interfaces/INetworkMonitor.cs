using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Interfaces;

public interface INetworkMonitor : IMonitor
{
    IReadOnlyList<NetworkConnection> GetCurrentConnections();
}


