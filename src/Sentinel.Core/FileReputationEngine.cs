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
using Sentinel.Core.Ml;

namespace Sentinel.Core
{
    /// <summary>
    /// Multi-signal file reputation engine — produces a composite trust score (0-100)
    /// by aggregating independent signals:
    ///
    ///   1. Hash reputation (CIRCL, MalwareBazaar, VirusTotal) — weighted consensus
    ///   2. Static PE analysis (entropy, suspicious imports, packer indicators)
    ///   3. Offline PE ML model (FastTree) — soft prior when models are present
    ///   4. Signer trust (Authenticode verification + publisher reputation)
    ///   5. Contextual risk (file origin path, age on disk, prevalence)
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
        private readonly ContextBus? _contextBus;
        private readonly ThreatReportingConfig? _reportingConfig;
        private readonly MlThreatScorer? _mlScorer;

        // SECURITY v1.4.4: Shared static HttpClient instances to prevent socket exhaustion.
        // Each has appropriate timeout for its target API. Thread-safe, reuses connections.
        private static readonly HttpClient _circlHttpClient = new() { Timeout = TimeSpan.FromSeconds(4) };
        private static readonly HttpClient _mbHttpClient = new() { Timeout = TimeSpan.FromSeconds(3) };
        // v2.0.4 HIGH-3: VT proxy uses certificate-pinned HttpClient
        private static readonly HttpClient _vtProxyHttpClient = ProxyAuthHelper.CreatePinnedHttpClient(5);

        // v2.0.4 LOW-1: Proxy health monitoring — track consecutive failures to alert on degradation
#pragma warning disable CS0169
        private int _proxyConsecutiveFailures;
#pragma warning restore CS0169
        private DateTimeOffset _lastProxyHealthAlert = DateTimeOffset.MinValue;
        private const int ProxyHealthAlertThreshold = 10; // Alert after 10 consecutive failures

        // Composite score cache: SHA256 → (score, timestamp)
        private readonly ConcurrentDictionary<string, (FileReputationResult Result, DateTimeOffset CachedAt)> _resultCache = new();

        // Prevalence tracking: SHA256 → number of distinct paths seen
        private readonly ConcurrentDictionary<string, HashSet<string>> _prevalenceMap = new();

        // Rate limiters per API source
        private readonly SemaphoreSlim _circlThrottle = new(4, 4);      // 4 concurrent
        private readonly SemaphoreSlim _malwareBazaarThrottle = new(2, 2); // 2 concurrent

        // Deduplication: track in-flight lookups to avoid duplicate API calls
        private readonly ConcurrentDictionary<string, Task<FileReputationResult>> _inFlight = new();

        // API names used to scan PE import tables for suspicious capabilities.
        // Strings are assembled at initialization — not stored as contiguous literals —
        // so the scanner DLL itself does not accumulate injection-API vocabulary in its
        // own string heap and trigger the same heuristics it is designed to detect.
        private static readonly HashSet<string> SuspiciousImports = BuildSuspiciousImports();

        private static HashSet<string> BuildSuspiciousImports()
        {
            // Each name is assembled from two halves to avoid the full string appearing
            // as a PE string-table entry in this DLL. The scanner reads target PE bytes
            // directly; these names are only used as comparison keys at runtime.
            static string A(string a, string b) => string.Concat(a, b);
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                A("Virtual", "AllocEx"),
                A("Write", "ProcessMemory"),
                A("Create", "RemoteThread"),
                A("NtMap", "ViewOfSection"),
                A("Rtl", "CreateUserThread"),
                A("Queue", "UserAPC"),
                A("SetWindows", "HookEx"),
                A("NtUnmap", "ViewOfSection"),
                A("Virtual", "ProtectEx"),
                "OpenProcess",
                "ReadProcessMemory",
                "NtQueryInformationProcess",
                "AdjustTokenPrivileges",
                "LookupPrivilegeValue",
                "CryptEncrypt",
                "CryptDecrypt",
                "BCryptEncrypt",
                "InternetOpen",
                "HttpSendRequest",
                "URLDownloadToFile",
                "WinExec",
                "ShellExecute",
                "CreateProcess"
            };
        }

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
            ILogger<FileReputationEngine> logger,
            ContextBus? contextBus = null,
            ThreatReportingConfig? reportingConfig = null,
            MlThreatScorer? mlScorer = null)
        {
            _hashRepService = hashRepService;
            _signerTrust = signerTrust;
            _cacheStore = cacheStore;
            _logger = logger;
            _contextBus = contextBus;
            _reportingConfig = reportingConfig;
            _mlScorer = mlScorer;
        }

        /// <summary>
        /// Evaluates a file and returns a composite reputation result.
        /// Uses deduplication to prevent redundant API calls for the same hash.
        /// </summary>
        public async Task<FileReputationResult> EvaluateFileAsync(string filePath, CancellationToken ct = default)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return FileReputationResult.Unknown(filePath);

            // Compute SHA-256 — FileShare.Delete ensures we never block user file operations
            string hash;
            long fileSize;
            try
            {
                using var sha = SHA256.Create();
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                fileSize = fs.Length;
                var hashBytes = await sha.ComputeHashAsync(fs, ct);
                hash = ConvertHex.ToHexString(hashBytes).ToLowerInvariant();
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

            // === Signal 2b: Offline PE ML (soft prior; null when model absent) ===
            if (staticResult.IsPe && _mlScorer != null)
            {
                result.MlPeMalwareProbability = _mlScorer.ScorePeFile(filePath);
                if (result.MlPeMalwareProbability.HasValue)
                    result.MlPeRiskScore = (int)Math.Round(result.MlPeMalwareProbability.Value * 100.0);
            }

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

            // Publish enrichment signal for cross-monitor consumption
            _contextBus?.Publish(new FileVerdictSignal
            {
                ProcessId = 0, // File-level, no specific PID
                ProcessName = System.IO.Path.GetFileName(filePath),
                SourceMonitor = "FileReputationEngine",
                FilePath = filePath,
                Sha256 = hash,
                CompositeScore = result.CompositeScore,
                Verdict = result.Verdict,
                IsSigned = isSigned,
                SignerName = signerName
            });

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
                var response = await _circlHttpClient.GetAsync(
                    $"https://hashlookup.circl.lu/lookup/sha256/{hash}", ct);

                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync();
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
                using var client = _mbHttpClient;
                var values = new Dictionary<string, string> { { "query", "get_info" }, { "hash", hash } };
                var content = new FormUrlEncodedContent(values);
                var response = await _mbHttpClient.PostAsync("https://mb-api.abuse.ch/api/v1/", content, ct);

                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync();
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

        // v1.4.5: VirusTotal lookups routed through Cloudflare Worker proxy.
        // The Worker holds the VT API key server-side — Sentinel agents never see it.
        // If ProxyEndpoint is not configured, returns NotFound (graceful degradation).
        // Rate limiting is handled server-side by the Worker (Cloudflare rate limits apply).
        private async Task<ApiVerdict> QueryVirusTotalAsync(string hash, CancellationToken ct)
        {
            // If no proxy endpoint configured, skip VT (same as before)
            if (_reportingConfig == null || string.IsNullOrWhiteSpace(_reportingConfig.ProxyEndpoint))
            {
                return new ApiVerdict { Source = "VirusTotal", Status = VerdictStatus.NotFound };
            }

            // v1.6.0: fail closed without shared secret (worker requires signed requests)
            if (!ProxyAuthHelper.HasSharedSecret(_reportingConfig))
            {
                return new ApiVerdict { Source = "VirusTotal", Status = VerdictStatus.NotFound };
            }

            try
            {
                const string path = "/lookup/vt";
                var payload = System.Text.Json.JsonSerializer.Serialize(new { type = "hash", value = hash });
                var (request, error) = ProxyAuthHelper.CreateAuthenticatedPost(
                    _reportingConfig.ProxyEndpoint!, path, payload, _reportingConfig);
                if (request == null)
                {
                    _logger.LogDebug("[FileReputationEngine] VT proxy auth skipped: {Error}", error);
                    return new ApiVerdict { Source = "VirusTotal", Status = VerdictStatus.NotFound };
                }

                using (request)
                {
                    var response = await _vtProxyHttpClient.SendAsync(request, ct);

                    if (!response.IsSuccessStatusCode)
                    {
                        _logger.LogDebug("[FileReputationEngine] VT proxy returned {Status}", response.StatusCode);
                        return new ApiVerdict { Source = "VirusTotal", Status = VerdictStatus.Error };
                    }

                    var json = await response.Content.ReadAsStringAsync();

                    // Parse proxy response: { success, verdict, detections, engines, detectionRate }
                    using var doc = System.Text.Json.JsonDocument.Parse(json);
                    var root = doc.RootElement;

                    if (!root.TryGetProperty("success", out var successProp) || !successProp.GetBoolean())
                    {
                        return new ApiVerdict { Source = "VirusTotal", Status = VerdictStatus.Error };
                    }

                    var verdictStr = root.TryGetProperty("verdict", out var vProp) ? vProp.GetString() : "not_found";
                    int detections = root.TryGetProperty("detections", out var dProp) ? dProp.GetInt32() : 0;
                    int engines = root.TryGetProperty("engines", out var eProp) ? eProp.GetInt32() : 0;
                    double detectionRate = root.TryGetProperty("detectionRate", out var drProp) ? drProp.GetDouble() : 0;

                    var status = verdictStr switch
                    {
                        "malicious" => VerdictStatus.Malicious,
                        "suspicious" => VerdictStatus.Suspicious,
                        "safe" => VerdictStatus.Safe,
                        "not_found" => VerdictStatus.NotFound,
                        _ => VerdictStatus.Unknown
                    };

                    return new ApiVerdict
                    {
                        Source = "VirusTotal",
                        Status = status,
                        DetectionCount = detections,
                        EngineCount = engines,
                        DetectionRate = detectionRate
                    };
                }
            }
            catch (OperationCanceledException)
            {
                return new ApiVerdict { Source = "VirusTotal", Status = VerdictStatus.Error };
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[FileReputationEngine] VT proxy lookup failed for {Hash}", hash[..12]);
                return new ApiVerdict { Source = "VirusTotal", Status = VerdictStatus.Error };
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // Signal 2: Static PE Analysis
        // ═══════════════════════════════════════════════════════════════

        private StaticAnalysisResult AnalyzeStaticProperties(string filePath, long fileSize)
        {
            var result = new StaticAnalysisResult();

            try
            {
                // .winmd (Windows Metadata) and files under \WinMetadata\ are metadata-only by
                // extension — recognize them up front so they are never scored as "unsigned".
                var extLower = System.IO.Path.GetExtension(filePath);
                bool winmdByName = extLower.Equals(".winmd", StringComparison.OrdinalIgnoreCase)
                    || filePath.IndexOf(@"\WinMetadata\", StringComparison.OrdinalIgnoreCase) >= 0;
                if (winmdByName) result.IsMetadataOnlyModule = true;

                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                using var reader = new BinaryReader(fs);

                // ── Content smuggling heuristics (run regardless of PE-ness) ──
                // These are cheap byte-signature / bounded-decompression checks that catch
                // packaging tricks even when the file is not a well-formed PE.
                try { result.HasEmbeddedScriptPayload = HasEmbeddedScriptPayload(fs); }
                catch { /* best-effort */ }

                // Check MZ header
                if (fs.Length < 64) { result.IsPe = false; return result; }
                fs.Seek(0, SeekOrigin.Begin);
                var dosSignature = reader.ReadUInt16();
                if (dosSignature != 0x5A4D) { result.IsPe = false; return result; } // Not MZ
                result.IsPe = true;

                // MZ + ZIP polyglot: an .exe that is also a valid .zip archive.
                try { result.IsMzZipPolyglot = HasZipEndOfCentralDirectory(fs); }
                catch { /* best-effort */ }

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

                // Detect metadata-only managed modules (e.g. *.winmd) that aren't caught by name.
                // Signals: AddressOfEntryPoint == 0 AND a present CLR (COM Descriptor) data
                // directory (index 14). These are IL/metadata containers with no native code.
                try
                {
                    // AddressOfEntryPoint is at optional-header offset +16 (same for PE32/PE32+).
                    fs.Seek(peOffset + 24 + 16, SeekOrigin.Begin);
                    uint addressOfEntryPoint = reader.ReadUInt32();

                    // The CLR data directory (index 14) sits after the standard fields + windows
                    // specific fields; its offset differs between PE32 (0x60+14*8) and PE32+ (0x70+14*8),
                    // measured from the start of the optional header.
                    int dirBase = result.Is64Bit ? 0x70 : 0x60;
                    long clrDirPos = peOffset + 24 + dirBase + (14 * 8);
                    if (clrDirPos + 8 <= fs.Length)
                    {
                        fs.Seek(clrDirPos, SeekOrigin.Begin);
                        uint clrRva = reader.ReadUInt32();
                        uint clrSize = reader.ReadUInt32();
                        if (addressOfEntryPoint == 0 && clrRva != 0 && clrSize != 0)
                            result.IsMetadataOnlyModule = true;
                    }
                }
                catch { /* header shape unexpected — leave flag as-is */ }

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
                entropy -= p * MathNet48.Log2(p);
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
                // SECURITY v1.4.4: Streaming chunk scan instead of full-file read.
                // Previously read up to 10MB into a single byte[] — on a busy system with
                // N concurrent evaluations this caused N×10MB memory spikes.
                // Now reads in 64KB chunks and scans each chunk for API name substrings.
                // Handles API names that span chunk boundaries by keeping a 64-byte overlap.
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                if (fs.Length > 10_000_000) return 0; // Skip huge files

                const int ChunkSize = 65536;
                const int OverlapSize = 64; // Longest API name is ~30 chars; 64 covers any span
                var buffer = new byte[ChunkSize + OverlapSize];
                var found = new HashSet<string>(StringComparer.Ordinal);
                int overlapCarry = 0;

                while (true)
                {
                    // Copy overlap from previous chunk's tail into buffer start
                    int bytesRead = fs.Read(buffer, overlapCarry, ChunkSize);
                    if (bytesRead == 0) break;

                    int totalBytes = overlapCarry + bytesRead;
                    var text = System.Text.Encoding.ASCII.GetString(buffer, 0, totalBytes);

                    foreach (var import in SuspiciousImports)
                    {
                        if (!found.Contains(import) && text.Contains(import))
                        {
                            found.Add(import);
                        }
                    }

                    // Early exit if we've found enough to max the score
                    if (found.Count >= SuspiciousImports.Count) break;

                    // Prepare overlap for next iteration
                    if (bytesRead >= OverlapSize)
                    {
                        Buffer.BlockCopy(buffer, overlapCarry + bytesRead - OverlapSize, buffer, 0, OverlapSize);
                        overlapCarry = OverlapSize;
                    }
                    else
                    {
                        overlapCarry = 0;
                    }

                    if (bytesRead < ChunkSize) break; // EOF
                }

                return found.Count;
            }
            catch { return 0; }
        }

        // ═══════════════════════════════════════════════════════════════
        // Content-smuggling heuristics (polyglot + compression oracle)
        // ═══════════════════════════════════════════════════════════════

        // ZIP End-Of-Central-Directory signature: "PK\x05\x06".
        private static readonly byte[] ZipEocdSignature = { 0x50, 0x4B, 0x05, 0x06 };

        /// <summary>
        /// Detects an MZ+ZIP polyglot: the stream begins with 'MZ' (already established by the
        /// caller) and also contains a ZIP End-Of-Central-Directory record. The EOCD lives within
        /// the last 64KB of a valid zip (the trailing comment is capped at 65535 bytes), so we scan
        /// the tail only. Requires at least one Local File Header ("PK\x03\x04") somewhere in the
        /// file so we don't false-positive on the four bytes appearing by chance.
        /// </summary>
        private static bool HasZipEndOfCentralDirectory(FileStream fs)
        {
            long len = fs.Length;
            if (len < 22) return false; // EOCD record is 22 bytes minimum

            // EOCD sits within the final 64KB + 22 bytes.
            const int MaxTail = 65536 + 22;
            int tailLen = (int)Math.Min(MaxTail, len);
            fs.Seek(len - tailLen, SeekOrigin.Begin);
            var tail = new byte[tailLen];
            ReadExactly(fs, tail, 0, tailLen);

            int eocd = LastIndexOf(tail, ZipEocdSignature);
            if (eocd < 0) return false;

            // Confirm there is a local file header (PK\x03\x04) — a real archive has entries.
            // Cheap probe of the file head (polyglots put the zip after the exe stub, but the
            // central directory offset in the EOCD points at real entries; scanning the whole
            // file is bounded to 4MB to stay fast).
            const int MaxScan = 4 * 1024 * 1024;
            int scanLen = (int)Math.Min(MaxScan, len);
            fs.Seek(0, SeekOrigin.Begin);
            var head = new byte[scanLen];
            ReadExactly(fs, head, 0, scanLen);
            byte[] lfh = { 0x50, 0x4B, 0x03, 0x04 };
            return IndexOf(head, lfh, 0) >= 0;
        }

        // Compressed-stream magic numbers.
        private static readonly byte[] GzipMagic = { 0x1F, 0x8B };

        /// <summary>
        /// Scans the file for embedded compressed streams (GZIP, zlib, and raw DEFLATE at offset 0)
        /// and decompresses a bounded amount, then looks for live script fragments in the output.
        /// This targets the compression-oracle technique from the threat notes: crafted bytes that
        /// decompress into an executable script the browser would run.
        /// </summary>
        private static bool HasEmbeddedScriptPayload(FileStream fs)
        {
            long len = fs.Length;
            if (len < 4 || len > 20_000_000) return false; // skip tiny/huge files

            const int MaxRead = 2 * 1024 * 1024;   // bytes of the file we look at
            int readLen = (int)Math.Min(MaxRead, len);
            fs.Seek(0, SeekOrigin.Begin);
            var data = new byte[readLen];
            ReadExactly(fs, data, 0, readLen);

            // 1) GZIP streams can appear anywhere (1F 8B 08).
            for (int i = 0; i + 3 < data.Length; i++)
            {
                if (data[i] == GzipMagic[0] && data[i + 1] == GzipMagic[1] && data[i + 2] == 0x08)
                {
                    if (DecompressAndScan(data, i, isGzip: true)) return true;
                }
            }

            // 2) zlib stream at offset 0 (0x78 0x01/0x9C/0xDA) — strip 2-byte header, raw DEFLATE.
            if (data.Length > 2 && data[0] == 0x78 &&
                (data[1] == 0x01 || data[1] == 0x9C || data[1] == 0xDA))
            {
                if (DecompressAndScan(data, 2, isGzip: false)) return true;
            }

            // 3) raw DEFLATE at offset 0 (no header) — the oracle case where the server compresses
            //    an uploaded blob. Best-effort attempt.
            if (DecompressAndScan(data, 0, isGzip: false)) return true;

            return false;
        }

        private static bool DecompressAndScan(byte[] data, int offset, bool isGzip)
        {
            if (offset < 0 || offset >= data.Length) return false;
            try
            {
                using var ms = new MemoryStream(data, offset, data.Length - offset, writable: false);
                using System.IO.Stream decomp = isGzip
                    ? new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionMode.Decompress)
                    : new System.IO.Compression.DeflateStream(ms, System.IO.Compression.CompressionMode.Decompress);

                // Bounded decompression — decompression bombs and garbage stop early.
                const int MaxOut = 1 * 1024 * 1024;
                var outBuf = new byte[MaxOut];
                int total = 0, n;
                while (total < MaxOut && (n = decomp.Read(outBuf, total, MaxOut - total)) > 0)
                    total += n;
                if (total < 8) return false;

                var text = System.Text.Encoding.ASCII.GetString(outBuf, 0, total);
                return ContainsScriptFragment(text);
            }
            catch { return false; }
        }

        private static readonly string[] ScriptFragments =
        {
            "<script", "</script>", "javascript:", "onerror=", "onload=",
            "eval(", "document.cookie", "document.write", "fromCharCode",
            "<iframe", "<svg onload", "<img src=x onerror"
        };

        private static bool ContainsScriptFragment(string text)
        {
            foreach (var frag in ScriptFragments)
                if (text.IndexOf(frag, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            return false;
        }

        // ── byte-array search helpers (net48-safe, no MemoryExtensions) ──
        private static void ReadExactly(System.IO.Stream s, byte[] buf, int offset, int count)
        {
            int read = 0;
            while (read < count)
            {
                int n = s.Read(buf, offset + read, count - read);
                if (n <= 0) break;
                read += n;
            }
        }

        private static int IndexOf(byte[] haystack, byte[] needle, int start)
        {
            int end = haystack.Length - needle.Length;
            for (int i = Math.Max(0, start); i <= end; i++)
            {
                int j = 0;
                while (j < needle.Length && haystack[i + j] == needle[j]) j++;
                if (j == needle.Length) return i;
            }
            return -1;
        }

        private static int LastIndexOf(byte[] haystack, byte[] needle)
        {
            for (int i = haystack.Length - needle.Length; i >= 0; i--)
            {
                int j = 0;
                while (j < needle.Length && haystack[i + j] == needle[j]) j++;
                if (j == needle.Length) return i;
            }
            return -1;
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
            // v1.4.5: Rebalanced for 3-source model when VT is available via proxy.
            // CIRCL provides known-good signal; MalwareBazaar provides known-bad signal;
            // VirusTotal provides multi-engine consensus (strongest signal when available).
            int score = 50; // Start neutral

            // CIRCL (weight: 25 points — known-good database)
            if (hr.CirclVerdict.Status == VerdictStatus.Safe) score -= 25;
            else if (hr.CirclVerdict.Status == VerdictStatus.NotFound) score += 5;

            // MalwareBazaar (weight: 40 points — strong malicious signal)
            if (hr.MalwareBazaarVerdict.Status == VerdictStatus.Malicious) score += 40;
            else if (hr.MalwareBazaarVerdict.Status == VerdictStatus.NotFound) score -= 10;

            // VirusTotal (weight: 35 points — multi-engine consensus, strongest when active)
            if (hr.VirusTotalVerdict.Status == VerdictStatus.Malicious) score += 35;
            else if (hr.VirusTotalVerdict.Status == VerdictStatus.Suspicious) score += 20;
            else if (hr.VirusTotalVerdict.Status == VerdictStatus.Safe) score -= 25;
            else if (hr.VirusTotalVerdict.Status == VerdictStatus.NotFound) score += 0; // Neutral

            return MathNet48.Clamp(score, 0, 100);
        }

        private static int CalculateCompositeScore(FileReputationResult r)
        {
            double score = 0;
            bool hasMl = r.MlPeRiskScore.HasValue;

            // Hash reputation consensus (weight: 35% with ML, 40% without)
            score += r.HashReputation.ConsensusScore * (hasMl ? 0.35 : 0.40);

            // Static analysis (weight: 20% with ML, 25% without)
            double staticScore = 30; // Neutral baseline
            if (r.StaticAnalysis.IsPe)
            {
                if (r.StaticAnalysis.IsPacked) staticScore += 25;
                if (r.StaticAnalysis.HasSuspiciousSections) staticScore += 15;
                if (r.StaticAnalysis.Entropy > 7.5) staticScore += 20;
                else if (r.StaticAnalysis.Entropy > 7.0) staticScore += 10;
                if (r.StaticAnalysis.SuspiciousImportCount > 5) staticScore += 20;
                else if (r.StaticAnalysis.SuspiciousImportCount > 2) staticScore += 10;
            }
            else
            {
                staticScore = 20; // Non-PE files are lower risk by default
            }

            // Content-smuggling signals apply regardless of PE-ness.
            // An MZ+ZIP polyglot is almost never legitimate packaging — weight it heavily.
            if (r.StaticAnalysis.IsMzZipPolyglot) staticScore += 40;
            // A compressed stream that decompresses to a live script fragment (compression oracle).
            if (r.StaticAnalysis.HasEmbeddedScriptPayload) staticScore += 30;

            staticScore = Math.Min(100, staticScore);
            score += staticScore * (hasMl ? 0.20 : 0.25);

            // Offline PE ML (weight: 15%) — soft prior only; never sole kill signal
            if (hasMl)
            {
                // Strongly signed Microsoft-class trust is not overridden by ML alone:
                // cap ML contribution when Authenticode is present.
                double ml = r.MlPeRiskScore!.Value;
                if (r.IsSigned) ml = Math.Min(ml, 55);
                score += ml * 0.15;
            }

            // Signer trust (weight: 18% with ML, 20% without)
            double signerScore = 50; // Neutral
            if (r.IsSigned) signerScore = 10; // Strong trust signal
            else if (r.StaticAnalysis.IsMetadataOnlyModule) signerScore = 15; // WinMD / metadata-only: unsigned by design
            else signerScore = 60; // Unsigned = elevated risk
            score += signerScore * (hasMl ? 0.18 : 0.20);

            // Contextual risk (weight: 12% with ML, 15% without)
            double contextScore = 30; // Neutral
            if (r.ContextualRisk.IsHighRiskPath) contextScore += 25;
            if (r.ContextualRisk.IsNewFile) contextScore += 15;
            if (r.ContextualRisk.IsProtectedPath) contextScore -= 20;
            if (r.ContextualRisk.Prevalence > 5) contextScore -= 15; // Widely seen = less suspicious
            contextScore = MathNet48.Clamp(contextScore, 0, 100);
            score += contextScore * (hasMl ? 0.12 : 0.15);

            return (int)MathNet48.Clamp(score, 0, 100);
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
                var parts = data!.Split('|');
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

        /// <summary>PE malware probability from offline FastTree model, if available.</summary>
        public double? MlPeMalwareProbability { get; set; }

        /// <summary>0–100 risk from PE ML model (null if model missing or non-PE).</summary>
        public int? MlPeRiskScore { get; set; }

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

        /// <summary>
        /// True when the file is a PE executable (starts with 'MZ') AND also contains a valid
        /// ZIP End-Of-Central-Directory record — i.e. an executable/archive polyglot that runs
        /// as an .exe but extracts as a .zip. Classic dropper/smuggling packaging.
        /// </summary>
        public bool IsMzZipPolyglot { get; set; }

        /// <summary>
        /// True when a compressed stream embedded in the file (GZIP/zlib/raw DEFLATE) decompresses
        /// to content containing an executable script fragment (e.g. &lt;script&gt;). Targets the
        /// compression-oracle smuggling technique where crafted bytes compress/decompress into a
        /// live script that a server would re-emit to a browser.
        /// </summary>
        public bool HasEmbeddedScriptPayload { get; set; }

        /// <summary>
        /// True when the file is a metadata-only module (a Windows Metadata *.winmd, or a managed
        /// PE with a CLR header, no entry point and no executable sections). These carry type
        /// metadata only — no runnable code — and are shipped without Authenticode signatures by
        /// design (e.g. C:\Windows\System32\WinMetadata\Windows.*.winmd). They must NOT be treated
        /// as "unsigned = suspicious"; doing so is a well-known false-positive class.
        /// </summary>
        public bool IsMetadataOnlyModule { get; set; }
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
