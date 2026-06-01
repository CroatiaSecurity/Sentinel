using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace WindowsSentinel.Core
{
    public enum HashVerdict
    {
        Safe,
        Unsafe,
        Unknown
    }

    public class HashReputationService
    {
        private readonly ConcurrentDictionary<string, HashVerdict> _memoryCache = new();
        private readonly SecureCacheStore _cacheStore;

        public HashReputationService(SecureCacheStore cacheStore)
        {
            _cacheStore = cacheStore;
        }

        public async Task<HashVerdict> GetVerdictAsync(string sha256)
        {
            if (string.IsNullOrWhiteSpace(sha256) || sha256.Length != 64)
            {
                return HashVerdict.Unknown;
            }

            sha256 = sha256.ToLowerInvariant();

            // Tier 1: In-memory cache
            if (_memoryCache.TryGetValue(sha256, out var verdict))
            {
                return verdict;
            }

            // Tier 2: DPAPI cache store
            var cachedVal = _cacheStore.Load("reputation", sha256);
            if (cachedVal != null && Enum.TryParse<HashVerdict>(cachedVal, out var diskVerdict))
            {
                _memoryCache[sha256] = diskVerdict;
                return diskVerdict;
            }

            // Perform mock reputation lookup (3-API consensus simulation)
            // In a real environment, this makes queries to MalwareBazaar, VirusTotal, etc.
            var liveVerdict = await FetchReputationFromApis(sha256);

            // Save to caches
            _memoryCache[sha256] = liveVerdict;
            _cacheStore.Save("reputation", sha256, liveVerdict.ToString());

            return liveVerdict;
        }

        private static Task<HashVerdict> FetchReputationFromApis(string sha256)
        {
            // Simulation: some predefined hashes for testing/threat validation
            if (sha256 == "0000000000000000000000000000000000000000000000000000000000000000")
            {
                return Task.FromResult(HashVerdict.Safe);
            }
            if (sha256 == "bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1")
            {
                return Task.FromResult(HashVerdict.Unsafe);
            }

            return Task.FromResult(HashVerdict.Unknown);
        }
    }
}
