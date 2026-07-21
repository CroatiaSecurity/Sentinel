using System;
using System.Collections.Generic;

namespace Sentinel.Core
{
    /// <summary>
    /// Loads IoCs from external encrypted cache (no hardcoded indicators).
    /// IoCs are managed via secure update mechanism, not compiled into the binary.
    /// </summary>
    public sealed class IoCScanner
    {
        private readonly SecureCacheStore _cacheStore;
        private readonly HashSet<string> _hashIoCs = new(StringComparer.OrdinalIgnoreCase);

        public IoCScanner(SecureCacheStore cacheStore)
        {
            _cacheStore = cacheStore;
            LoadFromCache();
        }

        private void LoadFromCache()
        {
            try
            {
                var data = _cacheStore.Load("ioc", "hashes");
                if (string.IsNullOrWhiteSpace(data)) return;

                // Format: one SHA256 hash per line
                foreach (var line in data.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    if (line.Length == 64 && !line.StartsWith('#')) // SHA256 hex length, skip comments
                        _hashIoCs.Add(line);
                }
            }
            catch
            {
                // Cache may not exist yet — degrade gracefully
            }
        }

        public void UpdateHashes(IEnumerable<string> hashes)
        {
            _hashIoCs.Clear();
            foreach (var h in hashes) _hashIoCs.Add(h);
            try
            {
                _cacheStore.Save("ioc", "hashes", string.Join('\n', _hashIoCs));
            }
            catch { }
        }

        public bool IsKnownBadHash(string hash)
        {
            return _hashIoCs.Contains(hash);
        }
    }
}
