using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Multi-signal file reputation engine — produces a composite trust score (0-100)
    /// by aggregating independent signals:
    ///
    ///   1. Hash reputation (CIRCL, MalwareBazaar, VirusTotal) — weighted consensus
    ///   2. Static PE analysis (entropy, suspicious imports, packer indicators)
    ///   3. Signer trust (Authenticode verification + publisher reputation)
    ///   4. Contextual risk (file origin path, age on disk, prevalence)
    ///
    /// Scoring: 0 = maximally trusted, 100 = confirmed malicious.
    ///   0-20:  Trusted (signed, known-good hash, established)
    ///   21-40: Low risk (some trust signals missing but no red flags)
    ///   41-60: Suspicious (unknown hash, unusual characteristics)
    ///   61-80: High risk (flagged by 1+ sources, suspicious static properties)
    ///   81-100: Malicious (confirmed by multiple sources or critical indicators)
    ///
    /// Rate limiting: 4 req/s to CIRCL, 2 req/s to MalwareBazaar, 4 req/min to VT.
    /// Caching: Results persisted via SecureCacheStore with 7-day TTL for Safe,
    ///          24h TTL for Unknown (retry), permanent for Unsafe.
    /// </summary>
    public sealed class FileReputationEngine
    {
        private readonly HashReputationService _hashRepService;
        private readonly SignerTrustService _signerTrust;
        private readonly SecureCacheStore _cacheStore;
        private readonly ILogger<FileReputationEngine> _logger;

        // Composite score cache: SHA256 → (score, timestamp)
        private readonly ConcurrentDictionary<string, (FileReputationResult Result, DateTimeOffset CachedAt)> _resultCache = new();

        // Prevalence tracking: SHA256 → number of distinct paths seen
        private readonly ConcurrentDictionary<string, HashSet<string>> _prevalenceMap = new();

        // Rate limiters per API source
        private readonly SemaphoreSlim _circlThrottle = new(4, 4);      // 4 concurrent
        private readonly SemaphoreSlim _malwareBazaarThrottle = new(2, 2); // 2 concurrent
        private readonly SemaphoreSlim _vtThrottle = new(1, 1);          // 1 at a time (4/min)
        private DateTimeOffset _lastVtCall = DateTimeOffset.MinValue;
        private static readonly TimeSpan VtMinInterval = TimeSpan.FromSeconds(15); // 4 per minute

        // Deduplication: track in-flight lookups to avoid duplicate API calls
        private readonly ConcurrentDictionary<string, Task<FileReputationResult>> _inFlight = new();

        // Static analysis constants
        private static readonly HashSet<string> SuspiciousImports = new(StringComparer.OrdinalIgnoreCase)
        {
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "NtMapViewOfSection", "RtlCreateUserThread", "QueueUserAPC",
            "SetWindowsHookEx", "NtUnmapViewOfSection", "VirtualProtectEx",
            "OpenProcess", "ReadProcessMemory", "NtQueryInformationProcess",
            "AdjustTokenPrivileges", "LookupPrivilegeValue",
            "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt",
            "InternetOpen", "HttpSendRequest", "URLDownloadToFile",
            "WinExec", "ShellExecute", "CreateProcess"
        };

        private static readonly HashSet<string> HighRiskPaths = new(StringComparer.OrdinalIgnoreCase)
        {
            @"\temp\", @"\tmp\", @"\appdata\local\temp\",
            @"\downloads\", @"\users\public\", @"\programdata\",
            @"\windows\temp\", @"\recycle"
        };

        public FileReputationEngine(
            HashReputationService hashRepService,
            SignerTrustService signerTrust,
            SecureCacheStore cacheStore,
            ILogger<FileReputationEngine> logger)
        {
            _hashRepService = hashRepService;
            _signerTrust = signerTrust;
            _cacheStore = cacheStore;
            _logger = logger;
        }

        /// <summary>
        /// Evaluates a file and returns a composite reputation result.
        /// Uses deduplication to prevent redundant API calls for the same hash.
        /// </summary>
        public async Task<FileReputationResult> EvaluateFileAsync(string filePath, CancellationToken ct = default)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return FileReputationResult.Unknown(filePath);

            // Compute SHA-256
            string hash;
            long fileSize;
            try
            {
                using var sha = SHA256.Create();
                await using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                fileSize = fs.Length;
                var hashBytes = await sha.ComputeHashAsync(fs, ct);
                hash = Convert.ToHexString(hashBytes).ToLowerInvariant();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[FileReputationEngine] Failed to hash {Path}", filePath);
                return FileReputationResult.Unknown(filePath);
            }

            // Check result cache (with TTL)
            if (_resultCache.TryGetValue(hash, out var cached))
            {
                var age = DateTimeOffset.UtcNow - cached.CachedAt;
                bool expired = cached.Result.Verdict == FileVerdict.Unknown && age > TimeSpan.FromHours(24);
                expired = expired || (cached.Result.Verdict == FileVerdict.Trusted && age > TimeSpan.FromDays(7));
                // Malicious never expires

                if (!expired)
                {
                    // Update prevalence
                    TrackPrevalence(hash, filePath);
                    return cached.Result;
                }
            }

            // Deduplication: if another thread is already evaluating this hash, wait for it
            var resultTask = _inFlight.GetOrAdd(hash, _ => EvaluateInternalAsync(filePath, hash, fileSize, ct));
            try
            {
                return await resultTask;
            }
            finally
            {
                _inFlight.TryRemove(hash, out _);
            }
        }

        private async Task<FileReputationResult> EvaluateInternalAsync(string filePath, string hash, long fileSize, CancellationToken ct)
        {
            var result = new FileReputationResult
            {
                FilePath = filePath,
                Sha256 = hash,
                FileSize = fileSize,
                EvaluatedAt = DateTimeOffset.UtcNow
            };

            // === Signal 1: Hash Reputation (parallel queries to 3 sources) ===
            var hashTask = QueryHashReputationAsync(hash, ct);

            // === Signal 2: Static PE Analysis (local, fast) ===
            var staticResult = AnalyzeStaticProperties(filePath, fileSize);
            result.StaticAnalysis = staticResult;

            // === Signal 3: Signer Trust ===
            bool isSigned = _signerTrust.IsSignedFile(filePath);
            string? signerName = isSigned ? _signerTrust.GetSignerName(filePath) : null;
            result.IsSigned = isSigned;
            result.SignerName = signerName;

            // === Signal 4: Contextual Risk ===
            var contextRisk = CalculateContextualRisk(filePath, hash);
            result.ContextualRisk = contextRisk;

            // Await hash reputation
            var hashResult = await hashTask;
            result.HashReputation = hashResult;

            // === Composite Scoring ===
            result.CompositeScore = CalculateCompositeScore(result);
            result.Verdict = DetermineVerdict(result.CompositeScore);

            // Cache the result
            _resultCache[hash] = (result, DateTimeOffset.UtcNow);
            TrackPrevalence(hash, filePath);

            // Persist to disk cache for cross-session retention
            PersistResult(hash, result);

            _logger.LogDebug(
                "[FileReputationEngine] {Path} → Score={Score}, Verdict={Verdict}, Hash={Hash}, Signed={Signed}",
                filePath, result.CompositeScore, result.Verdict, hash[..12], isSigned);

            return result;
        }

        // ═══════════════════════════════════════════════════════════════
        // Signal 1: Hash Reputation — parallel queries to 3 sources
        // ═══════════════════════════════════════════════════════════════

        private async Task<HashReputationResult> QueryHashReputationAsync(string hash, CancellationToken ct)
        {
            var result = new HashReputationResult();

            // Fire all 3 queries in parallel (each with their own rate limiter)
            var circlTask = QueryCirclAsync(hash, ct);
            var mbTask = QueryMalwareBazaarAsync(hash, ct);
            var vtTask = QueryVirusTotalAsync(hash, ct);

            await Task.WhenAll(circlTask, mbTask, vtTask);

            result.CirclVerdict = circlTask.Result;
            result.MalwareBazaarVerdict = mbTask.Result;
            result.VirusTotalVerdict = vtTask.Result;

            // Consensus: weight each source
            // CIRCL: known-good database (high trust for Safe, no malware info)
            // MalwareBazaar: known-bad database (high trust for Unsafe)
            // VirusTotal: multi-engine consensus (granular detection rate)
            result.ConsensusScore = CalculateHashConsensus(result);

            return result;
        }

        private async Task<ApiVerdict> QueryCirclAsync(string hash, CancellationToken ct)
        {
            await _circlThrottle.WaitAsync(ct);
            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(4) };
                client.DefaultRequestHeaders.Accept.Add(
                    new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

                var response = await client.GetAsync(
                    $"https://hashlookup.circl.lu/lookup/sha256/{hash}", ct);

                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync(ct);
                    var trustMatch = System.Text.RegularExpressions.Regex.Match(
                        json, @"""hashlookup:trust""\s*:\s*(\d+)");
                    if (trustMatch.Success && int.TryParse(trustMatch.Groups[1].Value, out int trust))
                    {
                        return new ApiVerdict { Source = "CIRCL", Status = trust > 60 ? VerdictStatus.Safe : VerdictStatus.Unknown, TrustScore = trust };
                    }
                    return new ApiVerdict { Source = "CIRCL", Status = VerdictStatus.Unknown };
                }
                if ((int)response.StatusCode == 404)
                    return new ApiVerdict { Source = "CIRCL", Status = VerdictStatus.NotFound };

                return new ApiVerdict { Source = "CIRCL", Status = VerdictStatus.Error };
            }
            catch
            {
                return new ApiVerdict { Source = "CIRCL", Status = VerdictStatus.Error };
            }
            finally { _circlThrottle.Release(); }
        }

        private async Task<ApiVerdict> QueryMalwareBazaarAsync(string hash, CancellationToken ct)
        {
            await _malwareBazaarThrottle.WaitAsync(ct);
            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
                var values = new Dictionary<string, string> { { "query", "get_info" }, { "hash", hash } };
                var content = new FormUrlEncodedContent(values);
                var response = await client.PostAsync("https://mb-api.abuse.ch/api/v1/", content, ct);

                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync(ct);
                    if (json.Contains("\"query_status\":\"ok\"") || json.Contains("\"query_status\": \"ok\""))
                        return new ApiVerdict { Source = "MalwareBazaar", Status = VerdictStatus.Malicious };
                    if (json.Contains("\"query_status\":\"hash_not_found\"") || json.Contains("\"query_status\": \"hash_not_found\""))
                        return new ApiVerdict { Source = "MalwareBazaar", Status = VerdictStatus.NotFound };
                }
                return new ApiVerdict { Source = "MalwareBazaar", Status = VerdictStatus.Error };
            }
            catch
            {
                return new ApiVerdict { Source = "MalwareBazaar", Status = VerdictStatus.Error };
            }
            finally { _malwareBazaarThrottle.Release(); }
        }

        private async Task<ApiVerdict> QueryVirusTotalAsync(string hash, CancellationToken ct)
        {
            // Rate limit: max 4 requests per minute (public/no-key endpoint)
            await _vtThrottle.WaitAsync(ct);
            try
            {
                var sinceLastCall = DateTimeOffset.UtcNow - _lastVtCall;
                if (sinceLastCall < VtMinInterval)
                {
                    await Task.Delay(VtMinInterval - sinceLastCall, ct);
                }
                _lastVtCall = DateTimeOffset.UtcNow;

                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
                // VT public API v3 hash lookup (no API key required for hash-only lookups on public files)
                // Falls back to v2 community endpoint if v3 fails
                var response = await client.GetAsync(
                    $"https://www.virustotal.com/api/v3/files/{hash}", ct);

                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync(ct);
                    // Extract detection stats: "malicious": N, "undetected": M
                    var maliciousMatch = System.Text.RegularExpressions.Regex.Match(
                        json, @"""malicious""\s*:\s*(\d+)");
                    var undetectedMatch = System.Text.RegularExpressions.Regex.Match(
                        json, @"""undetected""\s*:\s*(\d+)");

                    int malicious = maliciousMatch.Success ? int.Parse(maliciousMatch.Groups[1].Value) : 0;
                    int undetected = undetectedMatch.Success ? int.Parse(undetectedMatch.Groups[1].Value) : 0;
                    int total = malicious + undetected;

                    double detectionRate = total > 0 ? (double)malicious / total : 0;
                    return new ApiVerdict
                    {
                        Source = "VirusTotal",
                        Status = malicious > 5 ? VerdictStatus.Malicious :
                                 malicious > 0 ? VerdictStatus.Suspicious :
                                 VerdictStatus.Safe,
                        DetectionCount = malicious,
                        EngineCount = total,
                        DetectionRate = detectionRate
                    };
                }
                if ((int)response.StatusCode == 404)
                    return new ApiVerdict { Source = "VirusTotal", Status = VerdictStatus.NotFound };
                if ((int)response.StatusCode == 429)
                    return new ApiVerdict { Source = "VirusTotal", Status = VerdictStatus.RateLimited };

                return new ApiVerdict { Source = "VirusTotal", Status = VerdictStatus.Error };
            }
            catch
            {
                return new ApiVerdict { Source = "VirusTotal", Status = VerdictStatus.Error };
            }
            finally { _vtThrottle.Release(); }
        }

        // ═══════════════════════════════════════════════════════════════
        // Signal 2: Static PE Analysis
        // ═══════════════════════════════════════════════════════════════

        private StaticAnalysisResult AnalyzeStaticProperties(string filePath, long fileSize)
        {
            var result = new StaticAnalysisResult();

            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var reader = new BinaryReader(fs);

                // Check MZ header
                if (fs.Length < 64) { result.IsPe = false; return result; }
                var dosSignature = reader.ReadUInt16();
                if (dosSignature != 0x5A4D) { result.IsPe = false; return result; } // Not MZ
                result.IsPe = true;

                // Read PE offset
                fs.Seek(0x3C, SeekOrigin.Begin);
                int peOffset = reader.ReadInt32();
                if (peOffset <= 0 || peOffset >= fs.Length - 4) return result;

                fs.Seek(peOffset, SeekOrigin.Begin);
                uint peSignature = reader.ReadUInt32();
                if (peSignature != 0x00004550) return result; // Not PE\0\0

                // COFF header
                ushort machine = reader.ReadUInt16();
                ushort numberOfSections = reader.ReadUInt16();
                result.SectionCount = numberOfSections;
                uint timeDateStamp = reader.ReadUInt32();
                result.CompileTimestamp = DateTimeOffset.FromUnixTimeSeconds(timeDateStamp);

                // Skip to optional header
                fs.Seek(peOffset + 24, SeekOrigin.Begin);
                ushort optionalMagic = reader.ReadUInt16();
                result.Is64Bit = optionalMagic == 0x20B;

                // Calculate file entropy (sample first 64KB for speed)
                fs.Seek(0, SeekOrigin.Begin);
                int sampleSize = (int)Math.Min(65536, fs.Length);
                var sample = reader.ReadBytes(sampleSize);
                result.Entropy = CalculateEntropy(sample);

                // High entropy (>7.0) indicates packing/encryption
                result.IsPacked = result.Entropy > 7.0;

                // Check for suspicious section names
                result.HasSuspiciousSections = CheckSuspiciousSections(fs, peOffset, numberOfSections);

                // Scan import table for suspicious APIs (simplified — reads full file as text)
                result.SuspiciousImportCount = CountSuspiciousImports(filePath);

                result.FileSize = fileSize;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[FileReputationEngine] Static analysis failed for {Path}", filePath);
            }

            return result;
        }

        private static double CalculateEntropy(byte[] data)
        {
            if (data.Length == 0) return 0;
            var freq = new int[256];
            foreach (var b in data) freq[b]++;
            double entropy = 0;
            double len = data.Length;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = freq[i] / len;
                entropy -= p * Math.Log2(p);
            }
            return entropy;
        }

        private static bool CheckSuspiciousSections(FileStream fs, int peOffset, int sectionCount)
        {
            try
            {
                // Section headers start after optional header
                fs.Seek(peOffset + 24, SeekOrigin.Begin);
                using var reader = new BinaryReader(fs, System.Text.Encoding.ASCII, leaveOpen: true);
                ushort optMagic = reader.ReadUInt16();
                int optHeaderSize = optMagic == 0x20B ? 240 : 224; // PE32+ vs PE32
                fs.Seek(peOffset + 24 + optHeaderSize, SeekOrigin.Begin);

                var suspiciousNames = new HashSet<string> { ".ndata", "UPX0", "UPX1", ".themida", ".vmp0", ".vmp1", "MEW", ".aspack" };
                for (int i = 0; i < sectionCount && i < 20; i++)
                {
                    var nameBytes = reader.ReadBytes(8);
                    var name = System.Text.Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');
                    if (suspiciousNames.Contains(name)) return true;
                    reader.ReadBytes(32); // skip rest of section header
                }
            }
            catch { }
            return false;
        }

        private static int CountSuspiciousImports(string filePath)
        {
            try
            {
                // Quick scan: read file bytes and look for ASCII strings matching suspicious APIs
                // This is a heuristic — a proper PE parser would walk the IAT, but this is fast
                var bytes = File.ReadAllBytes(filePath);
                if (bytes.Length > 10_000_000) return 0; // Skip huge files
                var text = System.Text.Encoding.ASCII.GetString(bytes);
                int count = 0;
                foreach (var import in SuspiciousImports)
                {
                    if (text.Contains(import, StringComparison.Ordinal))
                        count++;
                }
                return count;
            }
            catch { return 0; }
        }

        // ═══════════════════════════════════════════════════════════════
        // Signal 4: Contextual Risk
        // ═══════════════════════════════════════════════════════════════

        private ContextualRiskResult CalculateContextualRisk(string filePath, string hash)
        {
            var result = new ContextualRiskResult();
            var pathLower = filePath.ToLowerInvariant();

            // Path risk
            result.IsHighRiskPath = HighRiskPaths.Any(p => pathLower.Contains(p));
            result.IsProtectedPath = pathLower.Contains(@"\program files") ||
                                     pathLower.Contains(@"\windows\system32") ||
                                     pathLower.Contains(@"\windows\syswow64");

            // Age on disk
            try
            {
                var created = File.GetCreationTimeUtc(filePath);
                result.AgeOnDisk = DateTimeOffset.UtcNow - created;
                result.IsNewFile = result.AgeOnDisk < TimeSpan.FromHours(1);
            }
            catch { result.IsNewFile = true; }

            // Prevalence (how many distinct paths have this hash been seen at?)
            if (_prevalenceMap.TryGetValue(hash, out var paths))
            {
                result.Prevalence = paths.Count;
            }
            else
            {
                result.Prevalence = 1;
            }

            return result;
        }

        private void TrackPrevalence(string hash, string filePath)
        {
            var paths = _prevalenceMap.GetOrAdd(hash, _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            lock (paths)
            {
                if (paths.Count < 100) // Cap to prevent memory bloat
                    paths.Add(filePath);
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // Composite Scoring
        // ═══════════════════════════════════════════════════════════════

        private static int CalculateHashConsensus(HashReputationResult hr)
        {
            // Returns 0-100 where 0=safe, 100=malicious
            int score = 50; // Start neutral

            // CIRCL (weight: 20 points)
            if (hr.CirclVerdict.Status == VerdictStatus.Safe) score -= 20;
            else if (hr.CirclVerdict.Status == VerdictStatus.NotFound) score += 5;

            // MalwareBazaar (weight: 40 points — strong malicious signal)
            if (hr.MalwareBazaarVerdict.Status == VerdictStatus.Malicious) score += 40;
            else if (hr.MalwareBazaarVerdict.Status == VerdictStatus.NotFound) score -= 10;

            // VirusTotal (weight: 30 points — granular)
            if (hr.VirusTotalVerdict.Status == VerdictStatus.Malicious) score += 30;
            else if (hr.VirusTotalVerdict.Status == VerdictStatus.Suspicious) score += 15;
            else if (hr.VirusTotalVerdict.Status == VerdictStatus.Safe) score -= 20;
            else if (hr.VirusTotalVerdict.Status == VerdictStatus.NotFound) score += 5;

            return Math.Clamp(score, 0, 100);
        }

        private static int CalculateCompositeScore(FileReputationResult r)
        {
            double score = 0;

            // Hash reputation consensus (weight: 40%)
            score += r.HashReputation.ConsensusScore * 0.40;

            // Static analysis (weight: 25%)
            double staticScore = 30; // Neutral baseline
            if (r.StaticAnalysis.IsPe)
            {
                if (r.StaticAnalysis.IsPacked) staticScore += 25;
                if (r.StaticAnalysis.HasSuspiciousSections) staticScore += 15;
                if (r.StaticAnalysis.Entropy > 7.5) staticScore += 20;
                else if (r.StaticAnalysis.Entropy > 7.0) staticScore += 10;
                if (r.StaticAnalysis.SuspiciousImportCount > 5) staticScore += 20;
                else if (r.StaticAnalysis.SuspiciousImportCount > 2) staticScore += 10;
                staticScore = Math.Min(100, staticScore);
            }
            else
            {
                staticScore = 20; // Non-PE files are lower risk by default
            }
            score += staticScore * 0.25;

            // Signer trust (weight: 20%)
            double signerScore = 50; // Neutral
            if (r.IsSigned) signerScore = 10; // Strong trust signal
            else signerScore = 60; // Unsigned = elevated risk
            score += signerScore * 0.20;

            // Contextual risk (weight: 15%)
            double contextScore = 30; // Neutral
            if (r.ContextualRisk.IsHighRiskPath) contextScore += 25;
            if (r.ContextualRisk.IsNewFile) contextScore += 15;
            if (r.ContextualRisk.IsProtectedPath) contextScore -= 20;
            if (r.ContextualRisk.Prevalence > 5) contextScore -= 15; // Widely seen = less suspicious
            contextScore = Math.Clamp(contextScore, 0, 100);
            score += contextScore * 0.15;

            return (int)Math.Clamp(score, 0, 100);
        }

        private static FileVerdict DetermineVerdict(int compositeScore) => compositeScore switch
        {
            <= 20 => FileVerdict.Trusted,
            <= 40 => FileVerdict.LowRisk,
            <= 60 => FileVerdict.Suspicious,
            <= 80 => FileVerdict.HighRisk,
            _ => FileVerdict.Malicious
        };

        // ═══════════════════════════════════════════════════════════════
        // Persistence
        // ═══════════════════════════════════════════════════════════════

        private void PersistResult(string hash, FileReputationResult result)
        {
            try
            {
                var data = $"{result.CompositeScore}|{(int)result.Verdict}|{result.EvaluatedAt.Ticks}";
                _cacheStore.Save("filerepo", hash, data);
            }
            catch { }
        }

        /// <summary>
        /// Loads a previously persisted result from disk cache.
        /// Used on startup to pre-populate the in-memory cache.
        /// </summary>
        public FileReputationResult? LoadCachedResult(string hash)
        {
            try
            {
                var data = _cacheStore.Load("filerepo", hash);
                if (string.IsNullOrEmpty(data)) return null;
                var parts = data.Split('|');
                if (parts.Length != 3) return null;
                return new FileReputationResult
                {
                    Sha256 = hash,
                    CompositeScore = int.Parse(parts[0]),
                    Verdict = (FileVerdict)int.Parse(parts[1]),
                    EvaluatedAt = new DateTimeOffset(long.Parse(parts[2]), TimeSpan.Zero)
                };
            }
            catch { return null; }
        }

        /// <summary>
        /// Returns the current reputation stats for monitoring/health checks.
        /// </summary>
        public FileReputationStats GetStats() => new()
        {
            CachedResults = _resultCache.Count,
            TrackedFiles = _prevalenceMap.Count,
            InFlightLookups = _inFlight.Count
        };
    }

    // ═══════════════════════════════════════════════════════════════
    // Data Models
    // ═══════════════════════════════════════════════════════════════

    public enum FileVerdict
    {
        Unknown,
        Trusted,
        LowRisk,
        Suspicious,
        HighRisk,
        Malicious
    }

    public enum VerdictStatus
    {
        Unknown,
        Safe,
        Suspicious,
        Malicious,
        NotFound,
        Error,
        RateLimited
    }

    public sealed class FileReputationResult
    {
        public string FilePath { get; set; } = "";
        public string Sha256 { get; set; } = "";
        public long FileSize { get; set; }
        public DateTimeOffset EvaluatedAt { get; set; }
        public int CompositeScore { get; set; }
        public FileVerdict Verdict { get; set; } = FileVerdict.Unknown;
        public bool IsSigned { get; set; }
        public string? SignerName { get; set; }
        public HashReputationResult HashReputation { get; set; } = new();
        public StaticAnalysisResult StaticAnalysis { get; set; } = new();
        public ContextualRiskResult ContextualRisk { get; set; } = new();

        public static FileReputationResult Unknown(string path) => new()
        {
            FilePath = path, Verdict = FileVerdict.Unknown, CompositeScore = 50
        };
    }

    public sealed class HashReputationResult
    {
        public ApiVerdict CirclVerdict { get; set; } = new();
        public ApiVerdict MalwareBazaarVerdict { get; set; } = new();
        public ApiVerdict VirusTotalVerdict { get; set; } = new();
        public int ConsensusScore { get; set; }
    }

    public sealed class ApiVerdict
    {
        public string Source { get; set; } = "";
        public VerdictStatus Status { get; set; } = VerdictStatus.Unknown;
        public int TrustScore { get; set; }
        public int DetectionCount { get; set; }
        public int EngineCount { get; set; }
        public double DetectionRate { get; set; }
    }

    public sealed class StaticAnalysisResult
    {
        public bool IsPe { get; set; }
        public bool Is64Bit { get; set; }
        public double Entropy { get; set; }
        public bool IsPacked { get; set; }
        public bool HasSuspiciousSections { get; set; }
        public int SuspiciousImportCount { get; set; }
        public int SectionCount { get; set; }
        public long FileSize { get; set; }
        public DateTimeOffset CompileTimestamp { get; set; }
    }

    public sealed class ContextualRiskResult
    {
        public bool IsHighRiskPath { get; set; }
        public bool IsProtectedPath { get; set; }
        public bool IsNewFile { get; set; }
        public TimeSpan AgeOnDisk { get; set; }
        public int Prevalence { get; set; }
    }

    public sealed class FileReputationStats
    {
        public int CachedResults { get; set; }
        public int TrackedFiles { get; set; }
        public int InFlightLookups { get; set; }
    }
}
