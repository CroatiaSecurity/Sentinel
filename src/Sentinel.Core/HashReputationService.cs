using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
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
        private readonly ThreatReportingConfig _config;
        private readonly ILogger<HashReputationService> _logger;

        // SECURITY v1.4.4: Shared HttpClient instances to prevent socket exhaustion (TIME_WAIT).
        // Previously created new HttpClient() per API call — under sustained load this exhausted
        // ephemeral ports. Static instances are thread-safe and reuse connections via HTTP/1.1 keep-alive.
        private static readonly System.Net.Http.HttpClient _circlClient = new()
        {
            Timeout = TimeSpan.FromSeconds(4),
            DefaultRequestHeaders = { Accept = { new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json") } }
        };
        private static readonly System.Net.Http.HttpClient _malwareBazaarClient = new()
        {
            Timeout = TimeSpan.FromSeconds(3)
        };

        public HashReputationService(
            SecureCacheStore cacheStore,
            ThreatReportingConfig config,
            ILogger<HashReputationService> logger)
        {
            _cacheStore = cacheStore;
            _config = config;
            _logger = logger;
        }

        public async Task<HashVerdict> GetVerdictAsync(string sha256, CancellationToken cancellationToken = default)
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
            var liveVerdict = await FetchReputationFromApis(sha256, cancellationToken);

            // HARDENING v1.3.0: Only cache definitive results (Safe or Unsafe).
            // Unknown means the APIs failed — don't persist it or the file will never be re-checked.
            if (liveVerdict != HashVerdict.Unknown)
            {
                _memoryCache[sha256] = liveVerdict;
                _cacheStore.Save("reputation", sha256, liveVerdict.ToString());
            }

            return liveVerdict;
        }

        private async Task<HashVerdict> FetchReputationFromApis(string sha256, CancellationToken cancellationToken)
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

            // Tier 1: CIRCL Hashlookup — fast-path for known-good files
            try
            {
                var circlResponse = await _circlClient.GetAsync(
                    $"https://hashlookup.circl.lu/lookup/sha256/{sha256}", cancellationToken);

                if (circlResponse.IsSuccessStatusCode)
                {
                    var circlJson = await circlResponse.Content.ReadAsStringAsync();
                    // Parse "hashlookup:trust" field — values above 60 indicate known-good software
                    var trustMatch = System.Text.RegularExpressions.Regex.Match(
                        circlJson, @"""hashlookup:trust""\s*:\s*(\d+)");
                    if (trustMatch.Success && int.TryParse(trustMatch.Groups[1].Value, out int trustScore) && trustScore > 60)
                    {
                        return HashVerdict.Safe;
                    }
                }
                // 404 = not in CIRCL database, fall through to MalwareBazaar
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "CIRCL hashlookup failed for hash {Hash}, falling through to MalwareBazaar", sha256);
            }

            // Tier 2: MalwareBazaar — known-malicious check
            try
            {
                if (!string.IsNullOrWhiteSpace(_config.MalwareBazaarApiKey))
                {
                    // Add API key per-request via message handler (can't set on shared client)
                }

                var values = new System.Collections.Generic.Dictionary<string, string>
                {
                    { "query", "get_info" },
                    { "hash", sha256 }
                };

                var content = new System.Net.Http.FormUrlEncodedContent(values);

                using var request = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Post, "https://mb-api.abuse.ch/api/v1/");
                request.Content = content;
                if (!string.IsNullOrWhiteSpace(_config.MalwareBazaarApiKey))
                {
                    request.Headers.Add("Auth-Key", _config.MalwareBazaarApiKey);
                }

                var response = await _malwareBazaarClient.SendAsync(request, cancellationToken);

                if (response.IsSuccessStatusCode)
                {
                    var responseString = await response.Content.ReadAsStringAsync();
                    if (responseString.Contains("\"query_status\": \"ok\"") || responseString.Contains("\"query_status\":\"ok\""))
                    {
                        return HashVerdict.Unsafe;
                    }
                    if (responseString.Contains("\"query_status\": \"hash_not_found\"") || responseString.Contains("\"query_status\":\"hash_not_found\""))
                    {
                        // SECURITY v1.4.4: Return Unknown, NOT Safe.
                        // Previously returned Safe here — treating absence of evidence as evidence of safety.
                        // Novel malware (zero-day payloads, custom implants) will ALWAYS be absent from
                        // both CIRCL and MalwareBazaar. Marking them Safe caused permanent caching of a
                        // false-safe verdict, fed trust scores to BeaconingDetector (+2 for Safe hash),
                        // and made custom implants effectively invisible to reputation-based detection.
                        //
                        // Now: only CIRCL trust score > 60 can positively confirm a file as Safe.
                        // Absent from both DBs = Unknown = will be re-checked on next scan cycle.
                        return HashVerdict.Unknown;
                    }
                }
                else
                {
                    // API returned error status — fail CLOSED, treat as suspicious
                    _logger.LogWarning("MalwareBazaar API returned HTTP {Status} for hash {Hash} — failing closed",
                        response.StatusCode, sha256);
                    return HashVerdict.Unknown;
                }
            }
            catch (Exception ex)
            {
                // HARDENING v1.3.0: Fail CLOSED on network/API failure.
                // Previously returned Unknown which was treated as "not blocked" by FileVerdictScanner.
                // Now we log a warning and return Unknown — but the caller (FileVerdictScanner) will
                // NOT mark the file as Safe, and it will be re-checked on next scan cycle.
                _logger.LogWarning(ex, "MalwareBazaar API call FAILED for hash {Hash} — failing closed (will retry)", sha256);
            }

            // HARDENING v1.3.0: If we reach here, BOTH APIs failed or returned non-definitive results.
            // Do NOT cache this result — return Unknown without saving to disk cache so the file
            // gets re-checked on the next scan cycle instead of being permanently marked "Unknown/Safe".
            return HashVerdict.Unknown;
        }
    }
}

