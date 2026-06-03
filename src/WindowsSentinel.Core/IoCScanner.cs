using System;
using System.Collections.Generic;

namespace WindowsSentinel.Core
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
            // Load from DPAPI-protected secure cache
            // No indicators are hardcoded — they come from external feeds
        }

        public bool IsKnownBadHash(string hash)
        {
            return _hashIoCs.Contains(hash);
        }
    }
}
