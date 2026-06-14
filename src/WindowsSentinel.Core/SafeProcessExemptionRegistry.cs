using System.Collections.Concurrent;

namespace WindowsSentinel.Core
{
    public class SafeProcessExemptionRegistry
    {
        private readonly ConcurrentDictionary<int, bool> _safePids = new();

        public void RegisterSafeProcess(int pid)
        {
            if (pid > 0)
            {
                _safePids[pid] = true;
            }
        }

        public bool IsSafeProcess(int pid)
        {
            return _safePids.ContainsKey(pid);
        }

        public void Remove(int pid)
        {
            _safePids.TryRemove(pid, out _);
        }
    }
}
