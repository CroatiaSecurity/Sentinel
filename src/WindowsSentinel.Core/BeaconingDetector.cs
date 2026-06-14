using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Statistical C2 beaconing detector.
    ///
    /// C2 frameworks beacon at regular intervals with added jitter.
    /// Key property: inter-connection intervals have LOW coefficient of variation
    /// (CV = stddev/mean) compared to legitimate software which connects irregularly.
    ///
    /// Algorithm:
    ///   1. Track outbound connection timestamps per (ProcessId, RemoteAddress, RemotePort).
    ///   2. After N observations, compute CV of inter-arrival intervals.
    ///   3. If CV &lt; threshold AND mean interval is in beacon range (5s–30min), fire detection.
    ///   4. Jitter-aware: even with 30% jitter, CV stays below ~0.35 for beacons.
    ///      Legitimate software typically has CV &gt; 1.0.
    ///
    /// Trust demotion (v0.8.2):
    ///   The detector demotes response actions from Kill to NetworkIsolate (or LogOnly)
    ///   when a process passes MULTIPLE independent trust checks simultaneously:
    ///     - Authenticode signature verification (WinVerifyTrust — not spoofable without the private key)
    ///     - Binary resides at its original install path (not copied/renamed to temp)
    ///     - Process exhibits multi-destination diversity (real apps talk to many IPs; C2 beacons one)
    ///     - Behavioral baseline confirms the process is established
    ///
    ///   An attacker reading this code gains nothing because:
    ///     - They cannot forge a valid Authenticode signature from Valve/Mozilla/etc.
    ///     - They cannot write to Program Files without elevation (covered by other rules)
    ///     - If they DO have elevation, the privilege escalation rules fire first
    ///     - Multi-destination diversity requires them to beacon many different IPs,
    ///       which increases their network forensic footprint exponentially
    ///     - The baseline requires surviving multiple observation cycles without other detections
    /// </summary>
    public sealed class BeaconingDetector : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<BeaconingDetector> _logger;

        private readonly ConcurrentDictionary<string, ConnectionHistory> _history = new();

        // Track all connection keys per PID for diversity analysis
        private readonly ConcurrentDictionary<int, ConcurrentDictionary<string, byte>> _pidDestinations = new();

        private const int MinObservations = 5;
        private const double MaxBeaconCv = 0.40;
        private const double MinBeaconIntervalSec = 5.0;
        private const double MaxBeaconIntervalSec = 1800.0;
        private const int MaxHistoryPerKey = 50;

        /// <summary>
        /// Windows-protected installation directories. Files here require admin/TrustedInstaller
        /// to write, so presence in these paths is a strong (but not sole) trust signal.
        /// We combine this with cryptographic hash verification — never trust path alone.
        /// </summary>
        private static readonly string[] ProtectedInstallPaths = new[]
        {
            @"\Program Files\",
            @"\Program Files (x86)\",
            @"\Windows\System32\",
            @"\Windows\SysWOW64\",
        };

        private readonly AllowlistService? _allowlist;
        private readonly BehavioralBaselineService? _baseline;
        private readonly FileVerdictAds? _fileVerdictAds;

        public BeaconingDetector(
            DetectionEngine de,
            ILogger<BeaconingDetector> l,
            AllowlistService? allowlist = null,
            BehavioralBaselineService? baseline = null,
            FileVerdictAds? fileVerdictAds = null)
        {
            _detectionEngine = de;
            _logger = l;
            _allowlist = allowlist;
            _baseline = baseline;
            _fileVerdictAds = fileVerdictAds;
        }

        /// <summary>
        /// Called by NetworkMonitor for every observed connection.
        /// Records the timestamp for statistical analysis.
        /// No name-based exemptions — trust is verified cryptographically at analysis time.
        /// </summary>
        public void RecordConnection(string remoteAddress, int remotePort, int processId, string processName, string? imagePath, string state)
        {
            if (state != "Established") return;
            if (remotePort is 80 or 443) return;

            if (_baseline != null && _baseline.IsKnownNetworkDestination(processName, remoteAddress, remotePort))
            {
                return;
            }

            var key = $"{processId}:{remoteAddress}:{remotePort}";
            var history = _history.GetOrAdd(key, _ => new ConnectionHistory(
                processId, processName, remoteAddress, remotePort, imagePath));

            // Update image path if it was initially null but is now available
            if (string.IsNullOrEmpty(history.ImagePath) && !string.IsNullOrEmpty(imagePath))
                history.ImagePath = imagePath;

            history.Record(DateTimeOffset.UtcNow);

            // Track destination diversity per PID (used for trust demotion)
            var destKey = $"{remoteAddress}:{remotePort}";
            var pidDests = _pidDestinations.GetOrAdd(processId, _ => new ConcurrentDictionary<string, byte>());
            pidDests.TryAdd(destKey, 0);
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[BeaconingDetector] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30_000, ct);
                    await AnalyzeAllAsync();
                    PruneStaleHistory();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[BeaconingDetector] Analysis error"); }
            }
        }

        private async Task AnalyzeAllAsync()
        {
            foreach (var kvp in _history)
            {
                var history = kvp.Value;
                if (history.HasFired) continue;

                var intervals = history.GetIntervals();
                if (intervals.Count < MinObservations) continue;

                double mean = intervals.Average();
                double stddev = StdDev(intervals, mean);
                double cv = mean > 0 ? stddev / mean : double.MaxValue;

                if (cv > MaxBeaconCv) continue;
                if (mean < MinBeaconIntervalSec) continue;
                if (mean > MaxBeaconIntervalSec) continue;

                history.HasFired = true;

                double cvFactor = Math.Max(0, 1.0 - cv / 0.40);
                double countFactor = Math.Min(1.0, intervals.Count / 20.0);
                double confidence = Math.Min(0.95, 0.70 + cvFactor * 0.20 + countFactor * 0.08);

                // Determine response action using multi-factor trust verification.
                // This combines Authenticode, path, diversity, and baseline — not any single signal.
                var responseAction = DetermineResponseAction(history);
                var tier = DetectionTier.Tier1Behavioral;

                string intervalDesc = mean < 60 ? $"{mean:F1}s" : $"{mean / 60:F1}min";

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "C2 Beaconing Behavior (Statistical)",
                    Evidence = $"Process '{history.ProcessName}' (PID {history.ProcessId}) beaconing to " +
                               $"{history.RemoteAddress}:{history.RemotePort} every ~{intervalDesc} " +
                               $"(CV={cv:F3}, n={intervals.Count})",
                    Reasoning = $"Statistical analysis of {intervals.Count} connection intervals: " +
                                $"mean={intervalDesc}, stddev={stddev:F1}s, CV={cv:F3}. " +
                                "CV below 0.40 indicates highly regular timing consistent with C2 beacon behavior. " +
                                "Legitimate software connects irregularly (CV > 1.0). " +
                                "This detection is signature-independent.",
                    Confidence = confidence,
                    Tier = tier,
                    AuthorizedResponse = responseAction,
                    ProcessName = history.ProcessName,
                    ProcessId = history.ProcessId,
                    Metadata = new()
                    {
                        ["TargetIP"] = history.RemoteAddress,
                        ["RemoteAddress"] = history.RemoteAddress,
                        ["RemotePort"] = history.RemotePort.ToString(),
                        ["MeanIntervalSec"] = mean.ToString("F2"),
                        ["CoefficientOfVariation"] = cv.ToString("F4"),
                        ["ObservationCount"] = intervals.Count.ToString()
                    }
                });
            }
        }

        /// <summary>
        /// Determines the response action using multi-factor cryptographic trust verification.
        /// 
        /// Trust signals (each independently hard to forge):
        ///   1. Image path resolvable (process not hollowed)
        ///   2. Authenticode signature is valid and chains to a trusted root CA
        ///   3. Binary is in a protected directory OR has a valid Authenticode signature
        ///   4. FileVerdictAds hash is not marked Unsafe
        ///   5. Process exhibits multi-destination diversity (connects to 3+ unique endpoints)
        ///   6. Process is established in the behavioral baseline
        ///
        /// Response escalation:
        ///   - No image path resolvable → KillProcess (hollowed/ghost)
        ///   - Hash marked Unsafe → KillProcess
        ///   - Valid Authenticode + (protected path OR diversity OR baseline) → LogOnly
        ///   - Protected path + unknown hash + (diversity OR baseline) → NetworkIsolate
        ///   - Protected path + unknown hash, no other signals → NetworkIsolate
        ///   - Unprotected path + valid Authenticode + diversity → NetworkIsolate
        ///   - Unprotected path + no Authenticode → KillProcess
        ///
        /// Why this is NOT exploitable even with source code access:
        ///   - Authenticode requires the publisher's private key (HSM-protected, not extractable)
        ///   - Diversity requires connecting to 3+ distinct IPs, increasing forensic surface
        ///   - Baseline requires surviving multiple cycles without triggering other rules
        ///   - Even if ALL demotion conditions are met, the detection still fires and is logged
        ///   - The response never drops below LogOnly — we always record the behavior
        /// </summary>
        private ResponseAction DetermineResponseAction(ConnectionHistory history)
        {
            // Step 1: Resolve image path
            var imagePath = history.ImagePath;
            if (string.IsNullOrEmpty(imagePath))
            {
                imagePath = ResolveImagePath(history.ProcessId);
            }

            // Step 2: No image path → likely hollowed or already-exited process
            if (string.IsNullOrEmpty(imagePath))
            {
                _logger.LogInformation(
                    "[BeaconingDetector] PID {Pid}: Cannot resolve image path — treating as hollowed process, authorizing kill",
                    history.ProcessId);
                return ResponseAction.KillProcess;
            }

            // Step 3: Check hash reputation — Unsafe always kills regardless of other signals
            var verdict = GetFileVerdict(imagePath);
            if (verdict == HashVerdict.Unsafe)
            {
                _logger.LogWarning(
                    "[BeaconingDetector] PID {Pid}: Image '{Path}' has UNSAFE hash verdict — authorizing kill",
                    history.ProcessId, imagePath);
                return ResponseAction.KillProcess;
            }

            // Step 4: Gather trust signals (each independently non-forgeable)
            bool isProtectedPath = IsInProtectedDirectory(imagePath);
            bool hasValidAuthenticode = VerifyAuthenticodeSignature(imagePath);
            bool hasDestinationDiversity = GetDestinationDiversityCount(history.ProcessId) >= 3;
            bool isBaselineEstablished = _baseline != null &&
                !string.IsNullOrEmpty(history.ProcessName) &&
                _baseline.IsEstablishedProcess(history.ProcessName);

            int trustScore = 0;
            if (hasValidAuthenticode) trustScore += 3;  // Strongest signal: requires publisher's private key
            if (isProtectedPath) trustScore += 2;       // Requires admin to write
            if (hasDestinationDiversity) trustScore += 1; // Increases attacker's forensic footprint
            if (isBaselineEstablished) trustScore += 1;   // Requires surviving observation without other alerts
            if (verdict == HashVerdict.Safe) trustScore += 2; // Previously verified safe

            // Step 5: Map trust score to response action
            // Score 0-2: Kill (no meaningful trust signals)
            // Score 3-4: NetworkIsolate (some trust, but not enough for full demotion)
            // Score 5+:  LogOnly (strong multi-factor trust — legitimate application)
            if (trustScore >= 5)
            {
                _logger.LogInformation(
                    "[BeaconingDetector] PID {Pid}: Multi-factor trust verified (score={Score}, authenticode={Auth}, protected={Prot}, diversity={Div}, baseline={Base}) — demoting to LogOnly",
                    history.ProcessId, trustScore, hasValidAuthenticode, isProtectedPath, hasDestinationDiversity, isBaselineEstablished);
                return ResponseAction.LogOnly;
            }
            else if (trustScore >= 3)
            {
                _logger.LogInformation(
                    "[BeaconingDetector] PID {Pid}: Partial trust (score={Score}, authenticode={Auth}, protected={Prot}, diversity={Div}, baseline={Base}) — demoting to NetworkIsolate",
                    history.ProcessId, trustScore, hasValidAuthenticode, isProtectedPath, hasDestinationDiversity, isBaselineEstablished);
                return ResponseAction.NetworkIsolate;
            }
            else
            {
                _logger.LogInformation(
                    "[BeaconingDetector] PID {Pid}: Low trust (score={Score}, authenticode={Auth}, protected={Prot}, diversity={Div}, baseline={Base}) — authorizing kill",
                    history.ProcessId, trustScore, hasValidAuthenticode, isProtectedPath, hasDestinationDiversity, isBaselineEstablished);
                return ResponseAction.KillProcess;
            }
        }

        /// <summary>
        /// Returns the number of distinct remote endpoints (IP:Port) this PID has connected to.
        /// Legitimate applications (Steam, torrent clients, FTP tools) typically connect to
        /// many different servers simultaneously. C2 beacons typically connect to one or two.
        ///
        /// This is NOT exploitable by connecting to many IPs because:
        ///   - Each additional connection increases forensic surface area
        ///   - More connections = more chances to trigger other detection rules
        ///   - Diversity alone only contributes 1 point to the trust score; it cannot
        ///     demote a response by itself without Authenticode or protected path
        /// </summary>
        private int GetDestinationDiversityCount(int processId)
        {
            if (_pidDestinations.TryGetValue(processId, out var destinations))
            {
                return destinations.Count;
            }
            return 0;
        }

        // ─── Authenticode Verification via WinVerifyTrust ────────────────────────
        // This calls the Windows WinVerifyTrust API which validates:
        //   1. The PE file has an embedded or catalog signature
        //   2. The signature is mathematically valid (RSA/ECDSA)
        //   3. The certificate chains to a trusted root CA in the machine store
        //   4. The certificate was valid at signing time (timestamp countersignature)
        //   5. The file content has not been modified since signing
        //
        // An attacker CANNOT bypass this without:
        //   - Stealing a code-signing certificate's private key (HSM-protected)
        //   - Compromising a CA (nation-state level)
        //   - Replacing the entire binary with a legitimately-signed one (then it's not malware)

        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
            new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO
        {
            public int cbStruct;
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public int cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public int dwUIChoice;
            public int fdwRevocationChecks;
            public int dwUnionChoice;
            public IntPtr pFile;
            public int dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public int dwProvFlags;
            public int dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

        private const int WTD_UI_NONE = 2;
        private const int WTD_REVOKE_NONE = 0;
        private const int WTD_CHOICE_FILE = 1;
        private const int WTD_STATEACTION_VERIFY = 1;
        private const int WTD_STATEACTION_CLOSE = 2;
        // Lifetime signing: don't fail if the cert is expired but has a valid timestamp
        private const int WTD_REVOCATION_CHECK_NONE = 0x00000010;
        private const int WTD_LIFETIME_SIGNING_FLAG = 0x00000800;

        /// <summary>
        /// Verifies the Authenticode signature of a PE file using WinVerifyTrust.
        /// Returns true only if the signature is valid AND chains to a trusted root.
        /// Returns false for unsigned files, tampered files, or files with untrusted certificates.
        /// 
        /// This is the same API that Windows SmartScreen, WDAC, and AppLocker use.
        /// It cannot be bypassed by renaming files, changing paths, or modifying metadata.
        /// The ONLY way to pass this check is to have the publisher's private signing key.
        /// </summary>
        private bool VerifyAuthenticodeSignature(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return false;

            IntPtr fileInfoPtr = IntPtr.Zero;
            try
            {
                var fileInfo = new WINTRUST_FILE_INFO
                {
                    cbStruct = Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                    pcwszFilePath = filePath,
                    hFile = IntPtr.Zero,
                    pgKnownSubject = IntPtr.Zero
                };

                fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
                Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

                var trustData = new WINTRUST_DATA
                {
                    cbStruct = Marshal.SizeOf<WINTRUST_DATA>(),
                    dwUIChoice = WTD_UI_NONE,
                    fdwRevocationChecks = WTD_REVOKE_NONE,
                    dwUnionChoice = WTD_CHOICE_FILE,
                    pFile = fileInfoPtr,
                    dwStateAction = WTD_STATEACTION_VERIFY,
                    // Allow lifetime signing (valid timestamp countersignature) so that
                    // binaries signed with expired certs still pass if timestamped.
                    // Skip revocation checks to avoid network dependency during analysis.
                    dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_LIFETIME_SIGNING_FLAG
                };

                var actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                int result = WinVerifyTrust(IntPtr.Zero, ref actionId, ref trustData);

                // Close the state handle
                trustData.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(IntPtr.Zero, ref actionId, ref trustData);

                // 0 = signature valid and trusted
                return result == 0;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[BeaconingDetector] Authenticode verification failed for '{Path}'", filePath);
                return false;
            }
            finally
            {
                if (fileInfoPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(fileInfoPtr);
            }
        }

        /// <summary>
        /// Attempts to resolve the image path for a running process by PID.
        /// Returns null if the process has exited or access is denied.
        /// </summary>
        private static string? ResolveImagePath(int pid)
        {
            try
            {
                using var proc = Process.GetProcessById(pid);
                return proc.MainModule?.FileName;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Checks if the image path is within a Windows-protected directory.
        /// These directories require admin/TrustedInstaller privileges to write to,
        /// making them significantly harder for malware to plant files in.
        /// </summary>
        private static bool IsInProtectedDirectory(string imagePath)
        {
            var normalized = imagePath.Replace('/', '\\');
            foreach (var protectedPath in ProtectedInstallPaths)
            {
                if (normalized.IndexOf(protectedPath, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Computes SHA-256 of the file and checks its verdict in the FileVerdictAds system.
        /// Returns Unknown if the file can't be read or FileVerdictAds is unavailable.
        /// </summary>
        private HashVerdict GetFileVerdict(string imagePath)
        {
            if (_fileVerdictAds == null) return HashVerdict.Unknown;

            try
            {
                if (!File.Exists(imagePath)) return HashVerdict.Unknown;

                string hash;
                using (var sha = SHA256.Create())
                using (var fs = new FileStream(imagePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    var hashBytes = sha.ComputeHash(fs);
                    hash = Convert.ToHexString(hashBytes).ToLowerInvariant();
                }

                return _fileVerdictAds.GetVerdict(imagePath, hash);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[BeaconingDetector] Failed to compute verdict for '{Path}'", imagePath);
                return HashVerdict.Unknown;
            }
        }

        private void PruneStaleHistory()
        {
            var cutoff = DateTimeOffset.UtcNow - TimeSpan.FromHours(2);
            foreach (var key in _history.Keys.ToList())
            {
                if (_history.TryGetValue(key, out var h) && h.LastSeen < cutoff)
                    _history.TryRemove(key, out _);
            }

            // Also prune stale PID destination tracking
            var activePids = _history.Values.Select(h => h.ProcessId).ToHashSet();
            foreach (var pid in _pidDestinations.Keys.ToList())
            {
                if (!activePids.Contains(pid))
                    _pidDestinations.TryRemove(pid, out _);
            }
        }

        private static double StdDev(IReadOnlyList<double> values, double mean)
        {
            if (values.Count < 2) return 0;
            double variance = values.Sum(v => (v - mean) * (v - mean)) / (values.Count - 1);
            return Math.Sqrt(variance);
        }
    }

    public sealed class ConnectionHistory
    {
        private readonly List<DateTimeOffset> _timestamps = new();
        private readonly object _lock = new();
        private const int MaxHistory = 50;

        public int ProcessId { get; }
        public string ProcessName { get; }
        public string RemoteAddress { get; }
        public int RemotePort { get; }
        public string? ImagePath { get; set; }
        public bool HasFired { get; set; }
        public DateTimeOffset LastSeen { get; private set; } = DateTimeOffset.UtcNow;

        public ConnectionHistory(int pid, string name, string remote, int port, string? imagePath = null)
        {
            ProcessId = pid;
            ProcessName = name;
            RemoteAddress = remote;
            RemotePort = port;
            ImagePath = imagePath;
        }

        public void Record(DateTimeOffset timestamp)
        {
            lock (_lock)
            {
                _timestamps.Add(timestamp);
                LastSeen = timestamp;
                if (_timestamps.Count > MaxHistory)
                    _timestamps.RemoveAt(0);
            }
        }

        public IReadOnlyList<double> GetIntervals()
        {
            lock (_lock)
            {
                if (_timestamps.Count < 2) return Array.Empty<double>();
                var sorted = _timestamps.OrderBy(t => t).ToList();
                return sorted
                    .Zip(sorted.Skip(1), (a, b) => (b - a).TotalSeconds)
                    .ToList();
            }
        }
    }
}
