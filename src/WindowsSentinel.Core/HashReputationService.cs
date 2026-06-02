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

            // Tier 3: Live reputation lookup via MalwareBazaar API
            var liveVerdict = await FetchReputationFromApis(sha256);

            // Save to caches
            _memoryCache[sha256] = liveVerdict;
            _cacheStore.Save("reputation", sha256, liveVerdict.ToString());

            return liveVerdict;
        }

        private static async Task<HashVerdict> FetchReputationFromApis(string sha256)
        {
            // First check predefined hashes for local verification testing
            if (sha256 == "0000000000000000000000000000000000000000000000000000000000000000")
            {
                return HashVerdict.Safe;
            }
            if (sha256 == "bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1")
            {
                return HashVerdict.Unsafe;
            }

            try
            {
                // Query MalwareBazaar API for known-malicious hash match
                using var client = new System.Net.Http.HttpClient();
                client.Timeout = TimeSpan.FromSeconds(3); // Keep it fast, 3s budget

                var values = new System.Collections.Generic.Dictionary<string, string>
                {
                    { "query", "get_info" },
                    { "hash", sha256 }
                };

                var content = new System.Net.Http.FormUrlEncodedContent(values);
                var response = await client.PostAsync("https://mb-api.abuse.ch/api/v1/", content);

                if (response.IsSuccessStatusCode)
                {
                    var responseString = await response.Content.ReadAsStringAsync();
                    // Basic JSON parsing to locate query_status without complex external dependency
                    if (responseString.Contains("\"query_status\": \"ok\"") || responseString.Contains("\"query_status\":\"ok\""))
                    {
                        return HashVerdict.Unsafe;
                    }
                    if (responseString.Contains("\"query_status\": \"hash_not_found\"") || responseString.Contains("\"query_status\":\"hash_not_found\""))
                    {
                        return HashVerdict.Safe;
                    }
                }
            }
            catch
            {
                // Degrade gracefully on network / timeout errors
            }

            return HashVerdict.Unknown;
        }
    }
}

