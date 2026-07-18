using System.Threading;
using System.Threading.Tasks;

namespace Behavedr.Core
{
    public interface IMonitor
    {
        string Name { get; }
        Task StartAsync(CancellationToken ct);
        Task StopAsync();
    }
}
