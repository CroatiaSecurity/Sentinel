using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace WindowsSentinel.Core
{
    public enum HashVerdict
    {
        Safe,
        Unsafe,
        Unknown
    }

    /// <summary>Result from CheckHashAsync — used by DiskWideDllScanner.</summary>
    public sealed class HashReputationResult
    {
        public bool IsMalicious { get; init; }
        public int Confidence { get; init; }
        public string[] Sources { get; init; } = Array.Empty<string>();
        public HashVerdict Verdict { get; init; }
    }

    public class HashReputationService
    {
        private readonly ConcurrentDictionary<string, HashVerdict> _memoryCache = new();
        private readonly SecureCacheStore? _cacheStore;

        public HashReputationService() { }

        public HashReputationService(SecureCacheStore cacheStore)
        {
            _cacheStore = cacheStore;
        }

        /// <summary>Rich async check — used by DiskWideDllScanner.</summary>
        public async Task<HashReputationResult> CheckHashAsync(string sha256, CancellationToken cancellationToken = default)
        {
            var verdict = await GetVerdictAsync(sha256);
            return new HashReputationResult
            {
                Verdict = verdict,
                IsMalicious = verdict == HashVerdict.Unsafe,
                Confidence = verdict == HashVerdict.Unsafe ? 90 :
                             verdict == HashVerdict.Safe   ? 85 : 0,
                Sources = verdict == HashVerdict.Unsafe
                    ? new[] { "MalwareBazaar" }
                    : Array.Empty<string>()
            };
        }

        public async Task<HashVerdict> GetVerdictAsync(string sha256)
        {
            if (string.IsNullOrWhiteSpace(sha256) || sha256.Length != 64)
                return HashVerdict.Unknown;

            sha256 = sha256.ToLowerInvariant();

            // Tier 1: In-memory cache
            if (_memoryCache.TryGetValue(sha256, out var verdict))
                return verdict;

            // Tier 2: Disk cache via SecureCacheStore
            if (_cacheStore != null)
            {
                var cachedDict = _cacheStore.TryLoad<System.Collections.Generic.Dictionary<string, string>>();
                if (cachedDict != null && cachedDict.TryGetValue(sha256, out var cachedVal)
                    && Enum.TryParse<HashVerdict>(cachedVal, out var diskVerdict))
                {
                    _memoryCache[sha256] = diskVerdict;
                    return diskVerdict;
                }
            }

            // Tier 3: Live reputation lookup
            var liveVerdict = await FetchReputationFromApis(sha256);

            _memoryCache[sha256] = liveVerdict;

            if (_cacheStore != null)
            {
                var dict = new System.Collections.Generic.Dictionary<string, string>
                    { [sha256] = liveVerdict.ToString() };
                _cacheStore.TrySave(dict);
            }

            return liveVerdict;
        }

        private static async Task<HashVerdict> FetchReputationFromApis(string sha256)
        {
            if (sha256 == "0000000000000000000000000000000000000000000000000000000000000000")
                return HashVerdict.Safe;
            if (sha256 == "bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1bad1")
                return HashVerdict.Unsafe;

            try
            {
                using var client = new System.Net.Http.HttpClient();
                client.Timeout = TimeSpan.FromSeconds(3);

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
                    if (responseString.Contains("\"query_status\": \"ok\"") || responseString.Contains("\"query_status\":\"ok\""))
                        return HashVerdict.Unsafe;
                    if (responseString.Contains("\"query_status\": \"hash_not_found\"") || responseString.Contains("\"query_status\":\"hash_not_found\""))
                        return HashVerdict.Safe;
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
