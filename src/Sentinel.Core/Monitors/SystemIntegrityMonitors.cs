// System Integrity Monitor Group — firewall, secure boot, scheduled tasks, TLS certificates, UAC, WMI persistence, and boot integrity

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    // ──────────────────────────────────────────────
    // Firewall Integrity Monitor — detects firewall rule tampering
    // ──────────────────────────────────────────────
    public sealed class FirewallIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<FirewallIntegrityMonitor> _logger;
        private int _baselineRuleCount;

        public FirewallIntegrityMonitor(DetectionEngine de, ILogger<FirewallIntegrityMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[FirewallIntegrityMonitor] Started");
            _baselineRuleCount = CountFirewallRules();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    var current = CountFirewallRules();
                    if (_baselineRuleCount > 0 && current > _baselineRuleCount + 5)
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Firewall Integrity: Bulk Rule Addition",
                            Evidence = $"Firewall rules increased from {_baselineRuleCount} to {current}",
                            Reasoning = "A significant number of firewall rules were added since baseline, indicating possible malware creating exceptions.",
                            Confidence = 0.70, Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });
                    }
                    _baselineRuleCount = current;
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[FirewallIntegrityMonitor] Error"); }
            }
        }

        private static int CountFirewallRules()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules");
                return key?.ValueCount ?? 0;
            }
            catch { return 0; }
        }
    }


    // ──────────────────────────────────────────────
    // Secure Boot Integrity Monitor — checks Secure Boot state
    // ──────────────────────────────────────────────
    public sealed class SecureBootIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<SecureBootIntegrityMonitor> _logger;

        public SecureBootIntegrityMonitor(DetectionEngine de, ILogger<SecureBootIntegrityMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[SecureBootIntegrityMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(300000, ct);
                    try
                    {
                        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
                        var val = key?.GetValue("UEFISecureBootEnabled");
                        if (val is int enabled && enabled == 0)
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Secure Boot: Disabled",
                                Evidence = "UEFI Secure Boot is disabled on this system",
                                Reasoning = "Secure Boot being disabled allows unsigned bootloaders and rootkits to load before the OS.",
                                Confidence = 0.50, Tier = DetectionTier.Tier2Indicator,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });
                        }
                    }
                    catch { }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[SecureBootIntegrityMonitor] Error"); }
            }
        }
    }


    // ──────────────────────────────────────────────
    // Scheduled Task Monitor — detects new/modified scheduled tasks
    // ──────────────────────────────────────────────
    public sealed class ScheduledTaskMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ScheduledTaskMonitor> _logger;
        private readonly HashSet<string> _baselineTasks = new(StringComparer.OrdinalIgnoreCase);

        public ScheduledTaskMonitor(DetectionEngine de, ILogger<ScheduledTaskMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ScheduledTaskMonitor] Started");
            SnapshotTasks(_baselineTasks);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    var current = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    SnapshotTasks(current);
                    foreach (var task in current.Except(_baselineTasks))
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Persistence: New Scheduled Task",
                            Evidence = $"New scheduled task: {task}",
                            Reasoning = "A new scheduled task was created, which is a common persistence mechanism for malware.",
                            Confidence = 0.65, Tier = DetectionTier.Tier2Indicator,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });
                        _baselineTasks.Add(task);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[ScheduledTaskMonitor] Error"); }
            }
        }

        private static void SnapshotTasks(HashSet<string> target)
        {
            var taskDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\Tasks");
            if (!Directory.Exists(taskDir)) return;
            try
            {
                foreach (var f in Directory.EnumerateFiles(taskDir, "*", SearchOption.AllDirectories))
                    target.Add(f);
            }
            catch { }
        }
    }


    // ──────────────────────────────────────────────
    // TLS Certificate Monitor — detects NEW root certificates added after baseline.
    // Startup: silently baselines all existing certs. Never alerts or removes.
    // Runtime: detects new certs not in baseline. Emits Tier2 log-only alerts.
    // Never auto-removes any certificate — alerts only for admin review.
    // ──────────────────────────────────────────────
    public sealed class TlsCertificateMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly JsonlEventLogger _eventLogger;
        private readonly ILogger<TlsCertificateMonitor> _logger;
        private readonly HashSet<string> _baselineThumbprints = new(StringComparer.OrdinalIgnoreCase);

        // Known enterprise TLS inspection CA subject patterns — these are legitimate
        // but still logged as Tier2 indicators for visibility
        private static readonly string[] KnownEnterpriseCAs =
        {
            "Zscaler", "Blue Coat", "BlueCoat", "Palo Alto", "Fortinet", "FortiGate",
            "Symantec WSS", "Cisco Umbrella", "McAfee", "Sophos", "Barracuda",
            "WatchGuard", "Check Point", "SonicWall", "Trend Micro", "iboss",
            "Websense", "Forcepoint", "Netskope", "Clearswift"
        };

        // Known developer/debugging tool CA patterns — Tier2 only, no removal
        private static readonly string[] KnownDevToolCAs =
        {
            "Fiddler", "DO_NOT_TRUST_FiddlerRoot", "Charles", "mitmproxy",
            "Burp", "BurpSuite", "OWASP ZAP", "Telerik"
        };

        public TlsCertificateMonitor(
            DetectionEngine de, SentinelConfig config, JsonlEventLogger logger,
            ILogger<TlsCertificateMonitor> l)
        {
            _detectionEngine = de; _config = config; _eventLogger = logger; _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[TlsCertificateMonitor] Started — performing startup full-store audit");

            // Phase 1: Startup scan — audit every existing cert, flag unknowns
            try
            {
                await AuditAndBaselineStoreAsync(ct);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[TlsCertificateMonitor] Startup audit failed");
            }

            _logger.LogInformation("[TlsCertificateMonitor] Audit complete: {Count} certs baselined", _baselineThumbprints.Count);

            // Phase 2: Runtime polling — detect new certs
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    await PollForNewCertsAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[TlsCertificateMonitor] Poll error"); }
            }
        }

        /// <summary>
        /// Startup audit: score every existing cert. Known public CAs are silently baselined.
        /// Unknown/suspicious certs that were present before Sentinel started get flagged as
        /// Tier2 indicators (can't auto-remove because we don't know if user installed them).
        /// This prevents the "race the baseline" attack from going completely unnoticed.
        /// </summary>
        private async Task AuditAndBaselineStoreAsync(CancellationToken ct)
        {
            var storesToAudit = new (System.Security.Cryptography.X509Certificates.StoreName Name, System.Security.Cryptography.X509Certificates.StoreLocation Location, string Label)[]
            {
                (System.Security.Cryptography.X509Certificates.StoreName.Root, System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine, "Root"),
                (System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher, System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine, "TrustedPublisher"),
                (System.Security.Cryptography.X509Certificates.StoreName.Root, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser, "UserRoot"),
                (System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser, "UserTrustedPublisher")
            };

            foreach (var (storeName, storeLocation, storeLabel) in storesToAudit)
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    using var store = new System.Security.Cryptography.X509Certificates.X509Store(storeName, storeLocation);
                    store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);

                    foreach (var cert in store.Certificates)
                    {
                        if (ct.IsCancellationRequested) break;

                        var key = $"{storeLabel}:{cert.Thumbprint}";
                        _baselineThumbprints.Add(key);

                        var analysis = AnalyzeCert(cert);

                        // Known public root CAs: fully trusted, no alert
                        if (analysis.IsPublicRootCa) continue;

                        // Known enterprise/dev tool CAs: log as Tier2 for visibility but no action
                        if (analysis.IsEnterpriseCa || analysis.IsDevTool)
                        {
                            await EmitCertDetectionAsync(cert, analysis, null, isStartupScan: true);
                            continue;
                        }

                        // Unknown cert with suspicious signals: flag it even though it was pre-existing
                        // This catches the "install cert before Sentinel starts" attack
                        if (analysis.Confidence >= 0.70)
                        {
                            _logger.LogWarning("[TlsCertificateMonitor] Startup: suspicious pre-existing cert in {Store}: {Subject} (confidence {Conf:F2})",
                                storeLabel, cert.Subject, analysis.Confidence);

                            // Very high confidence at startup (>=0.90): actively remove
                            // These are almost certainly attacker MitM certs planted before Sentinel started
                            ResponseAction? startupResponse = null;
                            if (analysis.Confidence >= 0.90 && _config.ActiveResponse)
                            {
                                startupResponse = ResponseAction.RemoveCert;
                                _logger.LogWarning("[TlsCertificateMonitor] REMOVING malicious pre-existing cert: {Subject}", cert.Subject);
                            }

                            await EmitCertDetectionAsync(cert, analysis, null, isStartupScan: false, startupResponse);
                            // Note: isStartupScan=false here so the response engine actually processes the removal
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "[TlsCertificateMonitor] Audit of {Store} failed", storeLabel);
                }
            }
        }

        /// <summary>
        /// Runtime polling: detect new certs added after baseline.
        /// New unknown certs with high confidence → remove + notify.
        /// New known public CAs → baseline silently.
        /// Monitors Root AND TrustedPublisher stores (BYOVD attack vector).
        /// </summary>
        private async Task PollForNewCertsAsync(CancellationToken ct)
        {
            await PollStoreAsync(
                System.Security.Cryptography.X509Certificates.StoreName.Root,
                System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine,
                "Root", ct);
            await PollStoreAsync(
                System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher,
                System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine,
                "TrustedPublisher", ct);
            await PollStoreAsync(
                System.Security.Cryptography.X509Certificates.StoreName.Root,
                System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser,
                "UserRoot", ct);
            await PollStoreAsync(
                System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher,
                System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser,
                "UserTrustedPublisher", ct);
        }

        private async Task PollStoreAsync(
            System.Security.Cryptography.X509Certificates.StoreName storeName,
            System.Security.Cryptography.X509Certificates.StoreLocation storeLocation,
            string storeLabel,
            CancellationToken ct)
        {
            try
            {
                using var store = new System.Security.Cryptography.X509Certificates.X509Store(storeName, storeLocation);
                store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);

                foreach (var cert in store.Certificates)
                {
                    if (ct.IsCancellationRequested) break;
                    var key = $"{storeLabel}:{cert.Thumbprint}";
                    if (_baselineThumbprints.Contains(key)) continue;

                    var analysis = AnalyzeCert(cert);
                    var adderInfo = TraceAdderProcess(cert.Thumbprint);

                    // Known public root CAs: baseline silently
                    if (analysis.IsPublicRootCa && analysis.Confidence <= 0.50)
                    {
                        _baselineThumbprints.Add(key);
                        continue;
                    }

                    // TrustedPublisher additions are extra suspicious — used for BYOVD
                    if (storeLabel == "TrustedPublisher")
                    {
                        analysis.Confidence = Math.Max(analysis.Confidence, 0.75);
                        analysis.Reasons.Add("Added to TrustedPublisher store (BYOVD/driver signing attack vector)");
                    }

                    _logger.LogWarning("[TlsCertificateMonitor] New cert in {Store}: Subject={Subject}, Confidence={Conf:F2}",
                        storeLabel, cert.Subject, analysis.Confidence);

                    ResponseAction response;
                    if (analysis.Confidence >= 0.80)
                    {
                        response = adderInfo != null ? ResponseAction.RemoveCertAndKillAdder : ResponseAction.RemoveCert;
                    }
                    else if (analysis.Confidence >= 0.65 && !analysis.IsEnterpriseCa && !analysis.IsDevTool)
                    {
                        response = ResponseAction.RemoveCert;
                    }
                    else
                    {
                        response = ResponseAction.LogOnly;
                    }

                    await EmitCertDetectionAsync(cert, analysis, adderInfo, isStartupScan: false, response);

                    // BYOVD chain trace: if a TrustedPublisher cert was removed,
                    // scan for drivers signed by this cert and quarantine them.
                    if (storeLabel == "TrustedPublisher" && response != ResponseAction.LogOnly)
                    {
                        await ScanAndQuarantineSignedDriversAsync(cert.Thumbprint, cert.Subject);
                    }

                    _baselineThumbprints.Add(key);
                }
            }
            catch { }
        }

        /// <summary>
        /// After removing a malicious code-signing cert from TrustedPublisher,
        /// scan the drivers directory for any .sys files signed by that cert.
        /// Quarantine the driver + remove its service registration.
        /// </summary>
        private async Task ScanAndQuarantineSignedDriversAsync(string certThumbprint, string certSubject)
        {
            try
            {
                // v1.8.1 RT-NEW-1: require a real thumbprint — never match by empty CN (Contains("") == true)
                if (string.IsNullOrWhiteSpace(certThumbprint) || certThumbprint.Length < 16)
                {
                    _logger.LogWarning("[TlsCertificateMonitor] BYOVD scan skipped — missing/short cert thumbprint");
                    return;
                }

                var driversDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers");
                if (!Directory.Exists(driversDir)) return;

                const int maxDriversPerCert = 5;
                int acted = 0;

                foreach (var driverPath in Directory.EnumerateFiles(driversDir, "*.sys"))
                {
                    if (acted >= maxDriversPerCert) break;

                    try
                    {
                        var signerCert = GetFileCertificate(driverPath);
                        if (signerCert == null) continue;

                        // EXACT thumbprint only — subject substring matching removed (empty CN bricked hosts)
                        bool matchesThumbprint = signerCert.Thumbprint?.Equals(
                            certThumbprint, StringComparison.OrdinalIgnoreCase) == true;
                        if (!matchesThumbprint) continue;

                        var driverName = Path.GetFileNameWithoutExtension(driverPath);

                        _logger.LogWarning("[TlsCertificateMonitor] BYOVD: driver '{Driver}' signed by removed cert (thumbprint match). Neutralizing service.", driverName);

                        await _eventLogger.LogEventAsync("response", new ResponseEvent
                        {
                            ProcessId = 0,
                            ProcessName = "TlsCertificateMonitor",
                            ActionTaken = "NEUTRALIZE_BYOVD_DRIVER",
                            Reason = $"Driver '{driverPath}' exact thumbprint match for removed TrustedPublisher cert '{certSubject}'. Stopping service + deleting service key. File NOT deleted from System32\\drivers (WRP-safe)."
                        });

                        // Stop service + remove registration. Do NOT delete the .sys under System32\drivers —
                        // WRP/OS integrity; mass-delete was a bricking risk when matching was too broad.
                        try
                        {
                            using var sc = new System.ServiceProcess.ServiceController(driverName);
                            if (sc.Status == System.ServiceProcess.ServiceControllerStatus.Running)
                                sc.Stop();
                        }
                        catch { }

                        try
                        {
                            using var servicesKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                                @"SYSTEM\CurrentControlSet\Services", writable: true);
                            servicesKey?.DeleteSubKeyTree(driverName, throwOnMissingSubKey: false);
                        }
                        catch { }

                        acted++;

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "BYOVD: Vulnerable Driver Neutralized",
                            Evidence = $"Driver '{driverName}.sys' matched removed TrustedPublisher thumbprint. Service registration removed. Binary left in place for OS integrity.",
                            Reasoning = "BYOVD neutralization stops the service and removes its SCM registration. " +
                                        "v1.8.1 no longer deletes System32\\drivers binaries (RT-NEW-1: empty-CN subject match could wipe all drivers).",
                            Confidence = 0.95,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = driverName,
                            ProcessId = 0,
                            Metadata = new Dictionary<string, string>
                            {
                                { "CertThumbprint", certThumbprint },
                                { "DriverPath", driverPath }
                            }
                        });
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[TlsCertificateMonitor] BYOVD driver scan error");
            }
        }

        private static System.Security.Cryptography.X509Certificates.X509Certificate2? GetFileCertificate(string filePath)
        {
            try
            {
#pragma warning disable SYSLIB0057 // CreateFromSignedFile is obsolete but has no X509CertificateLoader equivalent for Authenticode
                var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(
                    System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(filePath));
#pragma warning restore SYSLIB0057
                return cert;
            }
            catch { return null; }
        }

        // Known legitimate public root CA patterns — these are trusted global CAs
        private static readonly string[] KnownPublicRootCAs =
        {
            "DigiCert", "GlobalSign", "VeriSign", "Verizon", "Entrust", "GeoTrust",
            "GoDaddy", "Thawte", "Comodo", "Sectigo", "Starfield", "Let's Encrypt",
            "ISRG Root", "IdenTrust", "Baltimore", "CyberTrust", "QuoVadis",
            "Trustwave", "GTS Root", "GlobalTrust", "SwissSign", "Certum",
            "AffirmTrust", "Amazon Root", "Apple Root", "Microsoft Root", "Microsoft Corporation",
            "Chunghwa Telecom", "Hongkong Post", "Japan Registry", "WISeKey",
            "Buypass", "D-TRUST", "Telia", "Telekom", "Deutsche Telekom",
            "Staat der", "Government", "eID", "Network Solutions",
            "AddTrust", "USERTrust", "SECOM", "Unizeto", "TÜRKTRUST", "AC RAIZ",
            "Autoridad de Certificacion", "Certigna", "Certinomis", "ACCV",
            "ANF", "A-Trust", "BGC", "BNA", "CFCA", "China Internet", "CNNIC",
            "E-Tugra", "GDCA", "Hellenic", "HongKong Post", "Izenpe", "KISA",
            "KOICA", "Microsec", "NetLock", "OISTE", "PSC", "SK ID", "SSC",
            "StartCom", "TÜB", "TWCA", "VRK", "WoSign", "SecureSign", "Macao"
        };

        /// <summary>
        /// Analyzes a certificate and returns a confidence score + tier + reasoning.
        /// Key insight: ALL root CAs are self-signed by definition, so self-signed alone is NOT suspicious.
        /// We look for multiple corroborating attack indicators: short validity + no CRL + random name + expired.
        /// </summary>
        internal static CertAnalysisResult AnalyzeCert(System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
        {
            // Start with LOW base confidence — require MULTIPLE strong indicators to reach action threshold
            double confidence = 0.40;
            var tier = DetectionTier.Tier2Indicator;
            var reasons = new List<string>();

            var subject = cert.Subject ?? string.Empty;
            var issuer = cert.Issuer ?? string.Empty;

            // 1. Self-signed check (Subject == Issuer)
            // NOTE: All root CAs are self-signed! This is NORMAL, not suspicious.
            bool isSelfSigned = subject.Equals(issuer, StringComparison.OrdinalIgnoreCase);
            // DO NOT add confidence for self-signed — this is expected for root certs

            // 2. Check for known legitimate public root CA — downgrade to Tier2 immediately
            bool isPublicRootCA = KnownPublicRootCAs.Any(ca =>
                subject.Contains(ca, StringComparison.OrdinalIgnoreCase));

            // 3. Known enterprise CA — downgrade to Tier2, reduce confidence
            bool isEnterpriseCa = KnownEnterpriseCAs.Any(ca =>
                subject.Contains(ca, StringComparison.OrdinalIgnoreCase));

            // 4. Known dev tool — downgrade to Tier2, reduce confidence
            bool isDevTool = KnownDevToolCAs.Any(dt =>
                subject.Contains(dt, StringComparison.OrdinalIgnoreCase));

            // If it's a known legitimate CA (public, enterprise, or dev tool), cap confidence and downgrade tier
            if (isPublicRootCA)
            {
                tier = DetectionTier.Tier2Indicator;
                confidence = Math.Min(confidence, 0.50);
                reasons.Add("Known public root CA");
            }
            else if (isEnterpriseCa)
            {
                tier = DetectionTier.Tier2Indicator;
                confidence = Math.Min(confidence, 0.65);
                reasons.Add("Known enterprise TLS inspection CA");
            }
            else if (isDevTool)
            {
                tier = DetectionTier.Tier2Indicator;
                confidence = Math.Min(confidence, 0.55);
                reasons.Add("Known developer/debugging tool CA");
            }

            // Only apply suspicion signals if NOT a known legitimate CA
            if (!isPublicRootCA && !isEnterpriseCa && !isDevTool)
            {
                // 5. Short validity period (< 1 year — real root CAs are 10-25 years)
                var validity = cert.NotAfter - cert.NotBefore;
                if (validity.TotalDays < 365)
                {
                    confidence += 0.15; // Increased from 0.10 — this is a strong signal
                    reasons.Add($"Short validity ({validity.TotalDays:F0} days, expected 3650+)");
                }

                // 6. Very short validity (< 90 days — highly suspicious for a root CA)
                if (validity.TotalDays < 90)
                {
                    confidence += 0.10; // Increased from 0.05
                    reasons.Add("Extremely short validity (<90 days)");
                }

                // 7. No CRL Distribution Points or Authority Info Access (OCSP) — suspicious for a real CA
                bool hasCrl = false;
                bool hasOcsp = false;
                foreach (var ext in cert.Extensions)
                {
                    // OID 2.5.29.31 = CRL Distribution Points
                    if (ext.Oid?.Value == "2.5.29.31") hasCrl = true;
                    // OID 1.3.6.1.5.5.7.1.1 = Authority Information Access (OCSP)
                    if (ext.Oid?.Value == "1.3.6.1.5.5.7.1.1") hasOcsp = true;
                }

                if (!hasCrl && !hasOcsp)
                {
                    confidence += 0.15; // Increased from 0.10 — missing revocation is serious
                    reasons.Add("No CRL/OCSP distribution points");
                }

                // 8. Generic/random Subject CN — real CAs have well-known names
                var cn = ExtractCN(subject);
                if (!string.IsNullOrEmpty(cn))
                {
                    // Check for very short generic names or hex-like random strings
                    if (cn.Length <= 4)
                    {
                        confidence += 0.10;
                        reasons.Add($"Very short Subject CN: '{cn}'");
                    }
                    else if (cn.Length > 6 && IsHexLike(cn))
                    {
                        confidence += 0.15;
                        reasons.Add($"Random/hex-like Subject CN: '{cn}'");
                    }
                }

                // 9. Already expired — suspicious to install an expired root cert
                if (cert.NotAfter < DateTime.UtcNow)
                {
                    confidence += 0.10;
                    reasons.Add($"Already expired (NotAfter={cert.NotAfter:u})");
                }

                // 10. Suspicious keywords in subject — some malware uses obvious names
                var lowerSubject = subject.ToLowerInvariant();
                if (lowerSubject.Contains("test") || lowerSubject.Contains("fake") ||
                    lowerSubject.Contains("evil") || lowerSubject.Contains("malware") ||
                    lowerSubject.Contains("mitm") || lowerSubject.Contains("proxy"))
                {
                    confidence += 0.10;
                    reasons.Add("Suspicious keywords in Subject");
                }

                // 11. Machine-name CN (hostname pattern) — MitM certs generated by RDP/attack tools
                // Real CAs never have bare hostnames as their CN
                if (!string.IsNullOrEmpty(cn) && IsHostnameLike(cn))
                {
                    confidence += 0.25;
                    reasons.Add($"CN looks like a machine hostname: '{cn}'");
                }

                // 12. Absurd validity (>100 years) — attack certs use 999-year validity
                // No legitimate CA issues certs for more than 25 years
                if (validity.TotalDays > 36500) // >100 years
                {
                    confidence += 0.20;
                    reasons.Add($"Absurd validity period ({validity.TotalDays / 365:F0} years)");
                }

                // 13. Server Authentication EKU in root store — root CAs should NOT have
                // server auth EKU. Only leaf/intermediate certs need it. A root cert with
                // server auth EKU is designed for direct TLS interception.
                bool hasServerAuthEku = false;
                foreach (var ext in cert.Extensions)
                {
                    if (ext.Oid?.Value == "2.5.29.37") // Enhanced Key Usage
                    {
                        var ekuText = ext.Format(false);
                        if (ekuText.Contains("Server Authentication") || ekuText.Contains("1.3.6.1.5.5.7.3.1"))
                        {
                            hasServerAuthEku = true;
                            break;
                        }
                    }
                }
                if (hasServerAuthEku)
                {
                    confidence += 0.20;
                    reasons.Add("Root cert has Server Authentication EKU (designed for TLS interception)");
                }
            }

            // Cap confidence at 0.99
            confidence = Math.Min(confidence, 0.99);

            // High confidence unknown certs: promote to Tier1 so response engine acts on them
            if (!isPublicRootCA && !isEnterpriseCa && !isDevTool && confidence >= 0.80)
            {
                tier = DetectionTier.Tier1Behavioral;
            }

            return new CertAnalysisResult
            {
                Confidence = confidence,
                Tier = tier,
                Reasons = reasons,
                IsSelfSigned = isSelfSigned,
                IsPublicRootCa = isPublicRootCA,
                IsEnterpriseCa = isEnterpriseCa,
                IsDevTool = isDevTool,
                HasRevocationInfo = true // Simplified for this refactor
            };
        }

        /// <summary>
        /// Extracts the CN value from a distinguished name string.
        /// </summary>
        private static string ExtractCN(string distinguishedName)
        {
            // Subject format: "CN=Name, O=Org, ..." — extract CN value
            var parts = distinguishedName.Split(',');
            foreach (var part in parts)
            {
                var trimmed = part.Trim();
                if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                    return trimmed.Substring(3).Trim();
            }
            return string.Empty;
        }

        /// <summary>
        /// Checks if a string looks like a random hex/GUID string (common in attack certs).
        /// </summary>
        private static bool IsHexLike(string s)
        {
            int hexChars = 0;
            foreach (char c in s)
            {
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '-')
                    hexChars++;
            }
            return hexChars > s.Length * 0.7;
        }

        /// <summary>
        /// Checks if a CN looks like a machine hostname rather than a CA organization name.
        /// Hostnames are typically: DESKTOP-XXXXXXX, WIN-XXXXXXX, LAPTOP-XXXXXXX, or short
        /// uppercase alphanumeric strings without spaces or organization-like structure.
        /// </summary>
        private static bool IsHostnameLike(string cn)
        {
            if (string.IsNullOrEmpty(cn)) return false;
            // Contains spaces/commas/dots = org name, not hostname
            if (cn.Contains(' ') || cn.Contains(',') || cn.Contains('.')) return false;
            // Contains CA-like words = not a hostname
            var lower = cn.ToLowerInvariant();
            if (lower.Contains("root") || lower.Contains("ca") || lower.Contains("cert") ||
                lower.Contains("authority") || lower.Contains("trust") || lower.Contains("sign"))
                return false;

            var upper = cn.ToUpperInvariant();
            // Common Windows auto-generated hostname prefixes
            if (upper.StartsWith("WIN-") || upper.StartsWith("DESKTOP-") ||
                upper.StartsWith("LAPTOP-") || upper.StartsWith("WORKSTATION-") ||
                upper.StartsWith("PC-") || upper.StartsWith("SERVER-"))
                return true;
            // Matches local machine name — definitely a self-signed MitM cert
            try
            {
                var machineName = Environment.MachineName;
                if (cn.Equals(machineName, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            catch { }
            // All-caps with dash, 8-15 chars = likely Windows auto-generated hostname
            if (cn.Length >= 8 && cn.Length <= 15 && cn.Contains('-') &&
                cn.All(c => char.IsLetterOrDigit(c) || c == '-'))
                return true;
            return false;
        }

        /// <summary>
        /// Attempts to trace which process added a cert by querying the Security Event Log
        /// for recent registry write events to the cert store path.
        /// Returns the adder process info if found.
        /// </summary>
        private AdderProcessInfo? TraceAdderProcess(string thumbprint)
        {
            try
            {
                // Security Event ID 4657: A registry value was modified
                // The cert store is at: HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\{thumbprint}
                var log = new System.Diagnostics.EventLog("Security");
                var cutoff = DateTime.UtcNow.AddMinutes(-5);

                // Iterate backwards (most recent first) for efficiency
                for (int i = log.Entries.Count - 1; i >= 0 && i >= log.Entries.Count - 500; i--)
                {
                    try
                    {
                        var entry = log.Entries[i];
                        if (entry.TimeGenerated.ToUniversalTime() < cutoff) break;

                        // Event ID 4657 = Registry value modified (WRITE only)
                        // Do NOT use 4663 (Object access) - it fires on READS too, causing misattribution
                        if (entry.InstanceId != 4657) continue;

                        var message = entry.Message ?? string.Empty;

                        // Check if this event relates to the cert store
                        if (!message.Contains("SystemCertificates", StringComparison.OrdinalIgnoreCase) &&
                            !message.Contains("ROOT\\Certificates", StringComparison.OrdinalIgnoreCase))
                            continue;

                        // ONLY match events that contain our specific thumbprint
                        // Do NOT fall back to generic "ROOT\Certificates" matching - that causes
                        // misattribution when legitimate processes (browsers) touch the cert store
                        if (!string.IsNullOrEmpty(thumbprint) &&
                            !message.Contains(thumbprint, StringComparison.OrdinalIgnoreCase))
                            continue;

                        // Extract process info from the event
                        var processId = ExtractFieldFromEventMessage(message, "Process ID");
                        var processName = ExtractFieldFromEventMessage(message, "Process Name");

                        if (int.TryParse(processId?.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, null, out int pid) && pid > 4)
                        {
                            return new AdderProcessInfo
                            {
                                ProcessId = pid,
                                ProcessName = processName ?? "Unknown",
                                EventTimestamp = entry.TimeGenerated.ToUniversalTime()
                            };
                        }
                    }
                    catch { continue; }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[TlsCertificateMonitor] Failed to trace cert adder process");
            }

            return null;
        }

        /// <summary>
        /// Extracts a field value from a Windows Event Log message by field label.
        /// Event messages have format "Label:\t\tValue" or "Label:  Value".
        /// </summary>
        private static string? ExtractFieldFromEventMessage(string message, string fieldName)
        {
            var idx = message.IndexOf(fieldName + ":", StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return null;

            var start = idx + fieldName.Length + 1;
            if (start >= message.Length) return null;

            // Skip whitespace/tabs
            while (start < message.Length && (message[start] == ' ' || message[start] == '\t'))
                start++;

            var end = start;
            while (end < message.Length && message[end] != '\r' && message[end] != '\n')
                end++;

            return message.Substring(start, end - start).Trim();
        }

        /// <summary>
        /// Emits a detection event for a suspicious certificate.
        /// </summary>
        private async Task EmitCertDetectionAsync(
            System.Security.Cryptography.X509Certificates.X509Certificate2 cert,
            CertAnalysisResult analysis,
            AdderProcessInfo? adderInfo,
            bool isStartupScan,
            ResponseAction? overrideResponse = null)
        {
            var cn = ExtractCN(cert.Subject);
            var scanPhase = isStartupScan ? "Startup scan" : "Runtime detection";
            var reasonsList = string.Join("; ", analysis.Reasons);

            var evidence = $"{scanPhase}: Root cert Subject='{cert.Subject}', " +
                           $"Thumbprint={cert.Thumbprint}, " +
                           $"Validity={cert.NotBefore:yyyy-MM-dd}→{cert.NotAfter:yyyy-MM-dd}, " +
                           $"Signals=[{reasonsList}]";

            if (adderInfo != null)
            {
                evidence += $", Adder='{adderInfo.ProcessName}' PID={adderInfo.ProcessId} at {adderInfo.EventTimestamp:u}";
            }

            var reasoning = $"A new root certificate '{cn}' was added to the machine trust store. ";
            reasoning += "If unauthorized, this could enable TLS interception of HTTPS traffic. ";
            reasoning += $"Assessment signals: {reasonsList}.";

            var metadata = new Dictionary<string, string>
            {
                { "CertThumbprint", cert.Thumbprint },
                { "CertSubject", cert.Subject },
                { "CertIssuer", cert.Issuer },
                { "CertNotBefore", cert.NotBefore.ToString("o") },
                { "CertNotAfter", cert.NotAfter.ToString("o") },
                { "IsSelfSigned", analysis.IsSelfSigned.ToString() },
                { "IsEnterpriseCa", analysis.IsEnterpriseCa.ToString() },
                { "IsDevTool", analysis.IsDevTool.ToString() },
                { "HasRevocationInfo", analysis.HasRevocationInfo.ToString() },
                { "ScanPhase", isStartupScan ? "Startup" : "Runtime" }
            };

            if (adderInfo != null)
            {
                metadata["AdderProcessId"] = adderInfo.ProcessId.ToString();
                metadata["AdderProcessName"] = adderInfo.ProcessName;
            }

            var authorizedResponse = overrideResponse ?? ResponseAction.LogOnly;

            // Startup scans never auto-remove (user may have installed them intentionally)
            if (isStartupScan) authorizedResponse = ResponseAction.LogOnly;

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "TLS: Suspicious Root Certificate Detected",
                Evidence = evidence,
                Reasoning = reasoning,
                Confidence = analysis.Confidence,
                Tier = analysis.Tier,
                AuthorizedResponse = authorizedResponse,
                ProcessName = adderInfo?.ProcessName ?? "SYSTEM",
                ProcessId = adderInfo?.ProcessId ?? 0,
                Metadata = metadata
            });
        }


        /// <summary>Result of analyzing a single certificate.</summary>
        internal class CertAnalysisResult
        {
            public double Confidence { get; set; }
            public DetectionTier Tier { get; set; }
            public List<string> Reasons { get; set; } = new();
            public bool IsSelfSigned { get; set; }
            public bool IsPublicRootCa { get; set; }
            public bool IsEnterpriseCa { get; set; }
            public bool IsDevTool { get; set; }
            public bool HasRevocationInfo { get; set; }
        }

        /// <summary>Info about the process that added a cert to the store.</summary>
        private class AdderProcessInfo
        {
            public int ProcessId { get; set; }
            public string ProcessName { get; set; } = string.Empty;
            public DateTime EventTimestamp { get; set; }
        }
    }


    // ──────────────────────────────────────────────
    // UAC Bypass Surface Monitor — detects autoelevate binary abuse
    // ──────────────────────────────────────────────
    public sealed class UacBypassSurfaceMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<UacBypassSurfaceMonitor> _logger;

        // Auto-elevate binaries commonly abused for UAC bypass
        private static readonly string[] AutoElevateBinaries = {
            "fodhelper.exe", "computerdefaults.exe", "sdclt.exe", "eventvwr.exe", "slui.exe"
        };

        public UacBypassSurfaceMonitor(DetectionEngine de, ILogger<UacBypassSurfaceMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[UacBypassSurfaceMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(15000, ct);
                    foreach (var binName in AutoElevateBinaries)
                    {
                        var procs = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(binName));
                        foreach (var proc in procs)
                        {
                            try
                            {
                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "UAC Bypass: Auto-Elevate Binary Launched",
                                    Evidence = $"Auto-elevate binary '{proc.ProcessName}' running (PID {proc.Id})",
                                    Reasoning = "A Windows auto-elevate binary known to be abused for UAC bypass was detected running. Correlate with registry changes.",
                                    Confidence = 0.60, Tier = DetectionTier.Tier2Indicator,
                                    ProcessName = proc.ProcessName, ProcessId = proc.Id
                                });
                            }
                            catch { }
                            finally { proc.Dispose(); }
                        }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[UacBypassSurfaceMonitor] Error"); }
            }
        }
    }


    // ──────────────────────────────────────────────
    // Windows Update Integrity Monitor — checks WU tampering
    // ──────────────────────────────────────────────
    public sealed class WindowsUpdateIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WindowsUpdateIntegrityMonitor> _logger;

        public WindowsUpdateIntegrityMonitor(DetectionEngine de, ILogger<WindowsUpdateIntegrityMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WindowsUpdateIntegrityMonitor] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(600000, ct);
                    // Check if Windows Update service is disabled
                    try
                    {
                        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\wuauserv");
                        var startVal = key?.GetValue("Start");
                        if (startVal is int start && start == 4) // Disabled
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Tampering: Windows Update Service Disabled",
                                Evidence = "wuauserv service Start value is 4 (Disabled)",
                                Reasoning = "The Windows Update service was disabled, which prevents security patches and is a common malware persistence technique.",
                                Confidence = 0.75, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0
                            });
                        }
                    }
                    catch { }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[WindowsUpdateIntegrityMonitor] Error"); }
            }
        }
    }


    // ──────────────────────────────────────────────
    // WMI Persistence Monitor — detects WMI event subscriptions
    // ──────────────────────────────────────────────
    public sealed class WmiPersistenceMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WmiPersistenceMonitor> _logger;
        private readonly HashSet<string> _baselineSubscriptions = new(StringComparer.OrdinalIgnoreCase);

        public WmiPersistenceMonitor(DetectionEngine de, ILogger<WmiPersistenceMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WmiPersistenceMonitor] Started");
            SnapshotSubscriptions(_baselineSubscriptions);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    var current = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    SnapshotSubscriptions(current);
                    foreach (var sub in current.Except(_baselineSubscriptions))
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Persistence: New WMI Event Subscription",
                            Evidence = $"New WMI event subscription detected: '{sub}'",
                            Reasoning = "A new WMI event subscription was created, which is a common persistence and living-off-the-land technique.",
                            Confidence = 0.75, Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });
                        _baselineSubscriptions.Add(sub);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[WmiPersistenceMonitor] Error"); }
            }
        }

        private static void SnapshotSubscriptions(HashSet<string> target)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("root\\subscription",
                    "SELECT * FROM __EventConsumer");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var name = obj["Name"]?.ToString() ?? obj.GetHashCode().ToString();
                    target.Add(name);
                }
            }
            catch { }
        }
    }


    // ──────────────────────────────────────────────
    // Work Folders Exfil Monitor — detects mass file sync
    // ──────────────────────────────────────────────
    public sealed class WorkFoldersExfilMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WorkFoldersExfilMonitor> _logger;
        private long _baselineFileCount;

        public WorkFoldersExfilMonitor(DetectionEngine de, ILogger<WorkFoldersExfilMonitor> l) { _detectionEngine = de; _logger = l; }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WorkFoldersExfilMonitor] Started");
            var workFolders = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Work Folders");

            // Baseline file count
            if (Directory.Exists(workFolders))
            {
                try { _baselineFileCount = Directory.EnumerateFiles(workFolders, "*", SearchOption.AllDirectories).LongCount(); }
                catch { _baselineFileCount = 0; }
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    if (!Directory.Exists(workFolders)) continue;

                    long currentCount = 0;
                    try { currentCount = Directory.EnumerateFiles(workFolders, "*", SearchOption.AllDirectories).LongCount(); }
                    catch { continue; }

                    // If file count suddenly drops by 50+ files, possible bulk exfiltration/deletion
                    if (_baselineFileCount > 50 && currentCount < _baselineFileCount - 50)
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Data Exfiltration: Work Folders Mass File Removal",
                            Evidence = $"Work Folders file count dropped from {_baselineFileCount} to {currentCount} ({_baselineFileCount - currentCount} files removed)",
                            Reasoning = "A large number of files were removed from the Work Folders sync directory in a short period, which may indicate data exfiltration via sync or ransomware activity.",
                            Confidence = 0.70, Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });
                    }
                    // If file count increases dramatically (100+ new files added quickly) — staging for sync exfil
                    else if (currentCount > _baselineFileCount + 100)
                    {
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Data Exfiltration: Work Folders Mass File Addition",
                            Evidence = $"Work Folders file count increased from {_baselineFileCount} to {currentCount} ({currentCount - _baselineFileCount} files added)",
                            Reasoning = "A large number of files were rapidly added to the Work Folders sync directory, which may indicate data staging for cloud exfiltration.",
                            Confidence = 0.60, Tier = DetectionTier.Tier2Indicator,
                            ProcessName = "SYSTEM", ProcessId = 0
                        });
                    }

                    _baselineFileCount = currentCount;
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[WorkFoldersExfilMonitor] Error"); }
            }
        }
    }


    // ──────────────────────────────────────────────
    // Browser DNS Policy Guard — forces ALL apps to use OS DNS resolver (respects hosts file)
    // ──────────────────────────────────────────────
    public sealed class BrowserDnsPolicyGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<BrowserDnsPolicyGuard> _logger;
        private bool _initialEnforcement;
        private DateTime _lastTamperAlert = DateTime.MinValue;

        // Chromium-based browser policy keys (HKLM\SOFTWARE\Policies\...)
        private static readonly (string Key, string Name)[] ChromiumBrowsers = new[]
        {
            (@"SOFTWARE\Policies\Google\Chrome", "Chrome"),
            (@"SOFTWARE\Policies\Microsoft\Edge", "Edge"),
            (@"SOFTWARE\Policies\BraveSoftware\Brave", "Brave"),
            (@"SOFTWARE\Policies\Vivaldi", "Vivaldi"),
            (@"SOFTWARE\Policies\Opera Software\Opera", "Opera"),
            (@"SOFTWARE\Policies\Chromium", "Chromium"),
        };

        // Windows system-level DoH registry
        private const string DnsCacheParamsKey = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";
        private const string EnableAutoDohValue = "EnableAutoDoh";

        // Firefox uses a different mechanism — policies.json or registry
        private const string FirefoxPolicyKey = @"SOFTWARE\Policies\Mozilla\Firefox";
        private const string FirefoxDnsOverHttpsKey = @"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS";

        public BrowserDnsPolicyGuard(DetectionEngine de, ILogger<BrowserDnsPolicyGuard> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[BrowserDnsPolicyGuard] Started — enforcing OS DNS resolver for all browsers and disabling system DoH");

            await Task.Delay(10000, ct);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    bool anyChanged = false;

                    // 1. Disable Windows system-level DoH (EnableAutoDoh = 0)
                    anyChanged |= EnforceSystemDoh();

                    // 2. Enforce all Chromium browsers
                    foreach (var (key, name) in ChromiumBrowsers)
                        anyChanged |= EnforceChromiumPolicy(key, name);

                    // 3. Enforce Firefox
                    anyChanged |= EnforceFirefoxPolicy();

                    if (anyChanged && !_initialEnforcement)
                    {
                        _initialEnforcement = true;
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Hardening: System-Wide DNS Policy Enforced",
                            Evidence = "Disabled DNS-over-HTTPS system-wide (Windows DoH + all browser policies). " +
                                       "All DNS resolution now goes through the OS resolver which respects the hosts file.",
                            Reasoning = "DNS-over-HTTPS in browsers and at the OS level bypasses the local hosts file entirely. " +
                                        "Any hosts-file-based blocking (ads, trackers, malware domains) has zero effect when " +
                                        "DoH is active. Sentinel disables DoH at every layer: Windows DNS client, Chrome, Edge, " +
                                        "Brave, Vivaldi, Opera, Chromium, and Firefox. The hosts file becomes the single " +
                                        "authoritative DNS override point.",
                            Confidence = 0.99,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.SecurityEvasion,
                            Metadata = new Dictionary<string, string>
                            {
                                { "Action", "PolicyEnforced" },
                                { "EnableAutoDoh", "0" },
                                { "BuiltInDnsClientEnabled", "0" },
                                { "DnsOverHttpsMode", "off" },
                                { "Firefox.DNSOverHTTPS.Enabled", "false" }
                            }
                        });
                    }
                    else if (anyChanged && DateTime.UtcNow - _lastTamperAlert > TimeSpan.FromMinutes(5))
                    {
                        _lastTamperAlert = DateTime.UtcNow;
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Anti-Tamper: DNS Policy Reverted and Re-Applied",
                            Evidence = "DNS-over-HTTPS was found re-enabled (system or browser level). Re-enforced.",
                            Reasoning = "Something re-enabled DoH, bypassing the hosts file. Could be a Windows update, " +
                                        "browser update, user action, or malware circumventing DNS-level blocking.",
                            Confidence = 0.80,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.SecurityEvasion
                        });
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[BrowserDnsPolicyGuard] Error"); }

                await Task.Delay(15000, ct);
            }
        }

        /// <summary>
        /// Disables Windows system-level DNS-over-HTTPS.
        /// EnableAutoDoh: 0 = disabled, 2 = enabled.
        /// This ensures the OS DNS client uses plain DNS which reads the hosts file first.
        /// </summary>
        private bool EnforceSystemDoh()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(DnsCacheParamsKey, true);
                if (key == null) return false;

                var current = key.GetValue(EnableAutoDohValue);
                if (current != null && (int)current != 0)
                {
                    key.SetValue(EnableAutoDohValue, 0, RegistryValueKind.DWord);
                    _logger.LogDebug("[BrowserDnsPolicyGuard] Disabled system-level DoH (EnableAutoDoh=0)");
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[BrowserDnsPolicyGuard] Failed to enforce system DoH");
            }
            return false;
        }

        /// <summary>
        /// Enforces Chromium-based browser policies:
        /// - BuiltInDnsClientEnabled = 0 (use OS resolver)
        /// - DnsOverHttpsMode = "off"
        /// </summary>
        private bool EnforceChromiumPolicy(string policyKey, string browserName)
        {
            bool changed = false;
            try
            {
                // Only create the policy key if the browser is actually installed
                // (check if the parent policy path or browser exe exists)
                using var existingKey = Registry.LocalMachine.OpenSubKey(policyKey, true);
                var key = existingKey ?? Registry.LocalMachine.CreateSubKey(policyKey, true);
                if (key == null) return false;
                // If we created the key fresh, don't report as "changed" (avoids alert spam for uninstalled browsers)
                bool isNewKey = existingKey == null;

                var dnsClient = key.GetValue("BuiltInDnsClientEnabled");
                if (dnsClient == null || (int)dnsClient != 0)
                {
                    key.SetValue("BuiltInDnsClientEnabled", 0, RegistryValueKind.DWord);
                    if (!isNewKey) changed = true;
                    else _logger.LogDebug("[BrowserDnsPolicyGuard] Set BuiltInDnsClientEnabled=0 for {Browser} (new key)", browserName);
                }

                var dohMode = key.GetValue("DnsOverHttpsMode") as string;
                if (dohMode == null || !string.Equals(dohMode, "off", StringComparison.OrdinalIgnoreCase))
                {
                    key.SetValue("DnsOverHttpsMode", "off", RegistryValueKind.String);
                    if (!isNewKey) changed = true;
                    else _logger.LogDebug("[BrowserDnsPolicyGuard] Set DnsOverHttpsMode=off for {Browser} (new key)", browserName);
                }

                if (existingKey == null) key.Dispose();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[BrowserDnsPolicyGuard] Failed to enforce policy for {Browser}", browserName);
            }
            return changed;
        }

        /// <summary>
        /// Enforces Firefox DNS policy via registry:
        /// - DNSOverHTTPS\Enabled = 0 (disable DoH)
        /// - DNSOverHTTPS\Locked = 1 (prevent user from re-enabling)
        /// </summary>
        private bool EnforceFirefoxPolicy()
        {
            bool changed = false;
            try
            {
                using var key = Registry.LocalMachine.CreateSubKey(FirefoxDnsOverHttpsKey, true);
                if (key == null) return false;

                var enabled = key.GetValue("Enabled");
                if (enabled == null || (int)enabled != 0)
                {
                    key.SetValue("Enabled", 0, RegistryValueKind.DWord);
                    changed = true;
                    _logger.LogWarning("[BrowserDnsPolicyGuard] Enforced DNSOverHTTPS.Enabled=0 for Firefox");
                }

                var locked = key.GetValue("Locked");
                if (locked == null || (int)locked != 1)
                {
                    key.SetValue("Locked", 1, RegistryValueKind.DWord);
                    changed = true;
                    _logger.LogWarning("[BrowserDnsPolicyGuard] Enforced DNSOverHTTPS.Locked=1 for Firefox");
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[BrowserDnsPolicyGuard] Failed to enforce Firefox policy");
            }
            return changed;
        }
    }


    // ──────────────────────────────────────────────
    // Hosts File Guard — enforces embedded hosts content, deletes all other files in drivers\etc
    // ──────────────────────────────────────────────
    public sealed class HostsFileGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<HostsFileGuard> _logger;
        private FileSystemWatcher? _watcher;

        // The directory being protected
        private static readonly string DriversEtcPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "drivers", "etc");

        private static readonly string HostsFilePath = Path.Combine(DriversEtcPath, "hosts");

        // Debounce to avoid revert loops (our own writes trigger watcher events)
        private readonly ConcurrentDictionary<string, DateTime> _revertCooldown = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan CooldownPeriod = TimeSpan.FromSeconds(3);

        private readonly SemaphoreSlim _enforceLock = new(1, 1);

        // Precomputed SHA-256 of the trusted content for fast comparison
        private readonly string _trustedHash;

        public HostsFileGuard(DetectionEngine de, ILogger<HostsFileGuard> l)
        {
            _detectionEngine = de;
            _logger = l;
            using var sha = SHA256.Create();
            _trustedHash = Convert.ToHexString(sha.ComputeHash(new UTF8Encoding(false).GetBytes(TrustedHostsContent)));
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[HostsFileGuard] Started — enforcing hosts content and purging unauthorized files in {Path}", DriversEtcPath);

            if (!Directory.Exists(DriversEtcPath))
            {
                _logger.LogError("[HostsFileGuard] Directory not found: {Path}", DriversEtcPath);
                return;
            }

            // Initial enforcement
            await EnforceAsync("Startup", ct);

            // Set up FileSystemWatcher for the entire directory
            StartWatcher();

            // Periodic integrity verification (catches offline modifications)
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);
                    await EnforceAsync("PeriodicIntegrityCheck", ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[HostsFileGuard] Periodic check error");
                }
            }

            DisposeWatcher();
        }

        /// <summary>
        /// Core enforcement: write trusted content to hosts, delete everything else.
        /// </summary>
        private async Task EnforceAsync(string trigger, CancellationToken ct)
        {
            await _enforceLock.WaitAsync(ct);
            try
            {
                // 1. Enforce hosts file content
                await EnforceHostsFileAsync(trigger, ct);

                // 2. Delete all other files in the directory
                await DeleteUnauthorizedFilesAsync(trigger, ct);
            }
            finally
            {
                _enforceLock.Release();
            }
        }

        private async Task EnforceHostsFileAsync(string trigger, CancellationToken ct)
        {
            try
            {
                // Check if hosts file matches trusted content
                if (File.Exists(HostsFilePath))
                {
                    var currentHash = ComputeFileHash(HostsFilePath);
                    if (string.Equals(currentHash, _trustedHash, StringComparison.OrdinalIgnoreCase))
                        return; // Already correct
                }

                // File is modified or missing — revert
                _logger.LogWarning("[HostsFileGuard] hosts file diverged from trusted baseline (trigger: {Trigger})", trigger);

                var (pid, processName) = GetModifyingProcess(HostsFilePath);

                bool reverted = false;
                for (int i = 0; i < 3 && !reverted; i++)
                {
                    try
                    {
                        File.WriteAllText(HostsFilePath, TrustedHostsContent, new UTF8Encoding(false));
                        reverted = true;
                    }
                    catch (IOException) when (i < 2)
                    {
                        await Task.Delay(500, ct);
                    }
                }

                _revertCooldown[HostsFilePath] = DateTime.UtcNow;

                if (reverted)
                    _logger.LogWarning("[HostsFileGuard] Reverted hosts to trusted baseline");
                else
                    _logger.LogError("[HostsFileGuard] Failed to revert hosts after 3 attempts");

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Anti-Tamper: Hosts File Modification Reverted",
                    Evidence = $"hosts file was modified (trigger: {trigger}). " +
                               $"Reverted to embedded trusted baseline. Modifier: {processName} (PID {pid})",
                    Reasoning = "The Windows hosts file controls local DNS resolution. Malware modifies it " +
                                "to redirect traffic to C2 servers, block security updates, or perform DNS poisoning. " +
                                "Sentinel enforces the hardcoded trusted baseline at all times.",
                    Confidence = 0.95,
                    Tier = DetectionTier.Tier1Behavioral,
                    // Never kill on Startup — hosts file is expected to differ on first boot/install.
                    // Only kill if we have a valid PID and this isn't the initial enforcement.
                    AuthorizedResponse = (pid > 0 && trigger != "Startup") ? ResponseAction.KillProcessTree : ResponseAction.LogOnly,
                    ProcessName = processName,
                    ProcessId = pid,
                    SignalType = SignalType.AntiTamper,
                    Metadata = new Dictionary<string, string>
                    {
                        { "File", "hosts" },
                        { "Trigger", trigger },
                        { "Reverted", reverted.ToString() }
                    }
                });
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[HostsFileGuard] EnforceHostsFile error");
            }
        }

        private async Task DeleteUnauthorizedFilesAsync(string trigger, CancellationToken ct)
        {
            try
            {
                var allowedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "hosts", "services", "protocol", "networks", "lmhosts.sam"
                };

                foreach (var file in Directory.GetFiles(DriversEtcPath))
                {
                    var fileName = Path.GetFileName(file);
                    if (allowedFiles.Contains(fileName))
                        continue; // Keep standard system files

                    // Delete it
                    try
                    {
                        File.Delete(file);
                        _logger.LogWarning("[HostsFileGuard] Deleted unauthorized file: {File}", fileName);

                        _revertCooldown[file] = DateTime.UtcNow;

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "Anti-Tamper: Unauthorized File Deleted from drivers\\etc",
                            Evidence = $"File '{fileName}' existed in drivers\\etc and was deleted (trigger: {trigger}). " +
                                       "Only the 'hosts' file is permitted in this directory.",
                            Reasoning = "Files like hosts.ics, lmhosts.sam, and others in drivers\\etc can be " +
                                        "abused as DNS resolution bypass vectors. hosts.ics is loaded by the DNS " +
                                        "client alongside hosts and is a known attack surface. Sentinel removes " +
                                        "all files except the enforced hosts file.",
                            Confidence = 0.90,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM",
                            ProcessId = 0,
                            SignalType = SignalType.AntiTamper,
                            Metadata = new Dictionary<string, string>
                            {
                                { "File", fileName },
                                { "Trigger", trigger },
                                { "Action", "Deleted" }
                            }
                        });
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[HostsFileGuard] Failed to delete {File}", fileName);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[HostsFileGuard] DeleteUnauthorizedFiles error");
            }
        }

        private void StartWatcher()
        {
            try
            {
                _watcher = new FileSystemWatcher(DriversEtcPath)
                {
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName |
                                   NotifyFilters.CreationTime | NotifyFilters.Size,
                    Filter = "*",
                    IncludeSubdirectories = false,
                    EnableRaisingEvents = true
                };

                _watcher.Changed += OnFileEvent;
                _watcher.Created += OnFileEvent;
                _watcher.Renamed += (s, e) => OnFileEvent(s, e);

                _logger.LogInformation("[HostsFileGuard] Watcher active on {Path}", DriversEtcPath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[HostsFileGuard] Failed to start watcher");
            }
        }

        private async void OnFileEvent(object sender, FileSystemEventArgs e)
        {
            try
            {
                // Cooldown check
                if (_revertCooldown.TryGetValue(e.FullPath, out var lastAction) &&
                    DateTime.UtcNow - lastAction < CooldownPeriod)
                    return;

                await EnforceAsync(e.ChangeType.ToString(), CancellationToken.None);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[HostsFileGuard] OnFileEvent error for {File}", e.FullPath);
            }
        }

        private static (int pid, string name) GetModifyingProcess(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return (0, "Unknown");
                var lastWrite = File.GetLastWriteTimeUtc(filePath);
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        // Never target critical system processes or user shells — killing these causes BSOD or breaks user workflow
                        var name = proc.ProcessName;
                        if (string.Equals(name, "csrss", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "wininit", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "services", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "smss", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "lsass", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "svchost", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "winlogon", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "explorer", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "dwm", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "System", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "msiexec", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "TrustedInstaller", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "cmd", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "powershell", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(name, "pwsh", StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        if (proc.StartTime.ToUniversalTime() <= lastWrite &&
                            proc.StartTime.ToUniversalTime() > lastWrite.AddSeconds(-5) &&
                            proc.Id > 4)
                        {
                            return (proc.Id, name);
                        }
                    }
                    catch { }
                }
            }
            catch { }
            return (0, "Unknown");
        }

        private static string ComputeFileHash(string path)
        {
            try
            {
                using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sha = SHA256.Create();
                return Convert.ToHexString(sha.ComputeHash(stream));
            }
            catch { return string.Empty; }
        }

        private void DisposeWatcher()
        {
            if (_watcher != null)
            {
                _watcher.EnableRaisingEvents = false;
                _watcher.Dispose();
                _watcher = null;
            }
        }

        public override async Task StopAsync(CancellationToken ct)
        {
            DisposeWatcher();
            await base.StopAsync(ct);
        }

        // ── Embedded trusted hosts file content (no external file dependency) ──
        private const string TrustedHostsContent =
            "# Sentinel hosts file\r\n" +
            "127.0.0.1 localhost\r\n" +
            "127.0.0.1 localhost.localdomain\r\n" +
            "127.0.0.1 local\r\n" +
            "255.255.255.255 broadcasthost\r\n" +
            "::1 localhost\r\n" +
            "::1 ip6-localhost\r\n" +
            "::1 ip6-loopback\r\n" +
            "fe80::1%lo0 localhost\r\n" +
            "ff00::0 ip6-localnet\r\n" +
            "ff00::0 ip6-mcastprefix\r\n" +
            "ff02::1 ip6-allnodes\r\n" +
            "ff02::2 ip6-allrouters\r\n" +
            "ff02::3 ip6-allhosts\r\n" +
            "0.0.0.0 0.0.0.0\r\n" +
            // v1.7.6: forum.hr hosts block removed (opinionated). Watched by ForumHrWatchMonitor instead.
            "0.0.0.0 adtago.s3.amazonaws.com\r\n" +
            "0.0.0.0 analyticsengine.s3.amazonaws.com\r\n" +
            "0.0.0.0 advice-ads.s3.amazonaws.com\r\n" +
            "0.0.0.0 affiliationjs.s3.amazonaws.com\r\n" +
            "0.0.0.0 advertising-api-eu.amazon.com\r\n" +
            "0.0.0.0 ssl.google-analytics.com\r\n" +
            "0.0.0.0 fastclick.com\r\n" +
            "0.0.0.0 fastclick.net\r\n" +
            "0.0.0.0 media.fastclick.net\r\n" +
            "0.0.0.0 cdn.fastclick.net\r\n" +
            "0.0.0.0 analytics.yahoo.com\r\n" +
            "0.0.0.0 global.adserver.yahoo.com\r\n" +
            "0.0.0.0 ads.yap.yahoo.com\r\n" +
            "0.0.0.0 appmetrica.yandex.com\r\n" +
            "0.0.0.0 yandexadexchange.net\r\n" +
            "0.0.0.0 analytics.mobile.yandex.net\r\n" +
            "0.0.0.0 extmaps-api.yandex.net\r\n" +
            "0.0.0.0 adsdk.yandex.ru\r\n" +
            "0.0.0.0 appmetrica.yandex.com\r\n" +
            "0.0.0.0 hotjar.com\r\n" +
            "0.0.0.0 static.hotjar.com\r\n" +
            "0.0.0.0 api-hotjar.com\r\n" +
            "0.0.0.0 jotjar-analytics.com\r\n" +
            "0.0.0.0 mouseflow.com\r\n" +
            "0.0.0.0 freshmarketer.com\r\n" +
            "0.0.0.0 luckyorange.com\r\n" +
            "0.0.0.0 cdn.luckyorange.com\r\n" +
            "0.0.0.0 w1.luckyorange.com\r\n" +
            "0.0.0.0 upload.luckyorange.com\r\n" +
            "0.0.0.0 cs.luckyorange.com\r\n" +
            "0.0.0.0 settings.luckyorange.com\r\n" +
            "0.0.0.0 stats.wp.com\r\n" +
            "0.0.0.0 app.bugsnag.com\r\n" +
            "0.0.0.0 api.bugsnag.com\r\n" +
            "0.0.0.0 notify.bugsnag.com\r\n" +
            "0.0.0.0 sessions.bugsnag.com\r\n" +
            "0.0.0.0 browser.sentry-cdn.com\r\n" +
            "0.0.0.0 app.getsentry.com\r\n" +
            "0.0.0.0 amazonaws.com\r\n" +
            "0.0.0.0 amazonaax.com\r\n" +
            "0.0.0.0 amazonclix.com\r\n" +
            "0.0.0.0 assoc-amazon.com\r\n" +
            "0.0.0.0 ads.google.com\r\n" +
            "0.0.0.0 pagead2.googlesyndication.com\r\n" +
            "0.0.0.0 pagead2.googleadservices.com\r\n" +
            "# 0.0.0.0 facebook.com\r\n" +
            "0.0.0.0 amazon-adsystem.com\r\n" +
            "0.0.0.0 googleadservices.com\r\n" +
            "0.0.0.0 doubleclick.net\r\n" +
            "0.0.0.0 ad.doubleclick.net\r\n" +
            "0.0.0.0 static.doubleclick.net\r\n" +
            "0.0.0.0 m.doubleclick.net\r\n" +
            "0.0.0.0 mediavisor.doubleclick.net\r\n" +
            "0.0.0.0 googleads.g.doubleclick.net\r\n" +
            "0.0.0.0 adclick.g.doubleclick.net\r\n" +
            "0.0.0.0 carbonads.net\r\n" +
            "0.0.0.0 advertising.amazon.com\r\n" +
            "0.0.0.0 advertising.amazon.ca\r\n" +
            "0.0.0.0 google-analytics.com\r\n" +
            "0.0.0.0 doubleclick.net\r\n" +
            "0.0.0.0 doubleclick.com\r\n" +
            "0.0.0.0 doubleclick.de\r\n" +
            "0.0.0.0 partner.googleadservices.com\r\n" +
            "0.0.0.0 googlesyndication.com\r\n" +
            "0.0.0.0 google-analytics.com\r\n" +
            "0.0.0.0 zedo.com\r\n" +
            "0.0.0.0 amazon.ae\r\n" +
            "0.0.0.0 amazon.cn\r\n" +
            "0.0.0.0 advertising.amazon.co.jp\r\n" +
            "0.0.0.0 amazon.co.uk\r\n" +
            "0.0.0.0 advertising.amazon.com.au\r\n" +
            "0.0.0.0 advertising.amazon.com.mx\r\n" +
            "0.0.0.0 advertising.amazon.de\r\n" +
            "0.0.0.0 advertising.amazon.es\r\n" +
            "0.0.0.0 advertising.amazon.fr\r\n" +
            "0.0.0.0 advertising.amazon.in\r\n" +
            "0.0.0.0 advertising.amazon.it\r\n" +
            "0.0.0.0 advertising.amazon.sa\r\n" +
            "0.0.0.0 bingads.microsoft.com\r\n" +
            "0.0.0.0 adcash.com\r\n" +
            "0.0.0.0 taboola.com\r\n" +
            "0.0.0.0 outbrain.com\r\n" +
            "0.0.0.0 smartyads.com\r\n" +
            "0.0.0.0 popads.net\r\n" +
            "0.0.0.0 adpushup.com\r\n" +
            "0.0.0.0 trafficforce.com\r\n" +
            "0.0.0.0 adsterra.com\r\n" +
            "0.0.0.0 creative.ak.fbcdn.net\r\n" +
            "0.0.0.0 adbrite.com\r\n" +
            "0.0.0.0 exponential.com\r\n" +
            "0.0.0.0 quantserve.com\r\n" +
            "0.0.0.0 scorecardresearch.com\r\n" +
            "0.0.0.0 propellerads.com\r\n" +
            "0.0.0.0 admedia.net\r\n" +
            "0.0.0.0 admedia.com\r\n" +
            "0.0.0.0 bidvertiser.com\r\n" +
            "0.0.0.0 undertone.com\r\n" +
            "0.0.0.0 web.adblade.com\r\n" +
            "0.0.0.0 revenuehits.com\r\n" +
            "0.0.0.0 infolinks.com\r\n" +
            "0.0.0.0 vibrantmedia.com\r\n" +
            "0.0.0.0 ads.yahoosmallbusiness.com\r\n" +
            "0.0.0.0 ads.yahoo.com\r\n" +
            "0.0.0.0 hilltopads.net\r\n" +
            "0.0.0.0 clickadu.com\r\n" +
            "0.0.0.0 citysex.com\r\n" +
            "0.0.0.0 ad-maven.com\r\n" +
            "0.0.0.0 propelmedia.com\r\n" +
            "0.0.0.0 enginemediaexchange.com\r\n" +
            "0.0.0.0 advertisers.adversense.com\r\n" +
            "0.0.0.0 a.adtng.com\r\n" +
            "0.0.0.0 ads.facebook.com\r\n" +
            "0.0.0.0 an.facebook.com\r\n" +
            "0.0.0.0 analytics.facebook.com\r\n" +
            "0.0.0.0 pixel.facebook.com\r\n" +
            "0.0.0.0 ads.youtube.com\r\n" +
            "0.0.0.0 youtube.cleverads.vn\r\n" +
            "0.0.0.0 ads-twitter.com\r\n" +
            "0.0.0.0 ads-api.twitter.com\r\n" +
            "0.0.0.0 advertising.twitter.com\r\n" +
            "0.0.0.0 ads.linkedin.com\r\n" +
            "0.0.0.0 analytics.pointdrive.linkedin.com\r\n" +
            "0.0.0.0 ads.reddit.com\r\n" +
            "0.0.0.0 d.reddit.com\r\n" +
            "0.0.0.0 rereddit.com\r\n" +
            "0.0.0.0 events.redditmedia.com\r\n" +
            "0.0.0.0 analytics.tiktok.com\r\n" +
            "0.0.0.0 ads.tiktok.com\r\n" +
            "0.0.0.0 analytics-sg.tiktok.com\r\n" +
            "0.0.0.0 ads-sg.tiktok.com\r\n" +
            "# Google FCM push channel (blocks 443 fallback for Send Tab to Self attack)\r\n" +
            "0.0.0.0 mtalk.google.com\r\n" +
            "0.0.0.0 mobile-gtalk.l.google.com\r\n" +
            "0.0.0.0 alt1-mtalk.google.com\r\n" +
            "0.0.0.0 alt2-mtalk.google.com\r\n" +
            "0.0.0.0 alt3-mtalk.google.com\r\n" +
            "0.0.0.0 alt4-mtalk.google.com\r\n" +
            "0.0.0.0 alt5-mtalk.google.com\r\n" +
            "0.0.0.0 alt6-mtalk.google.com\r\n" +
            "0.0.0.0 alt7-mtalk.google.com\r\n" +
            "0.0.0.0 alt8-mtalk.google.com\r\n";
    }


    // ──────────────────────────────────────────────
    // Boot Integrity Guard — monitors bcdedit, EFI, and driver load order for rootkit persistence
    // ──────────────────────────────────────────────
    public sealed class BootIntegrityGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<BootIntegrityGuard> _logger;

        private Dictionary<string, string> _baselineBcd = new();
        private List<string> _baselineBootDrivers = new();
        private bool _baselineCaptured;

        private static readonly HashSet<string> TrustedBootDrivers = new(StringComparer.OrdinalIgnoreCase)
        {
            "WdBoot", "WdFilter", "Wof", "EhStorClass", "FileInfo",
            "hwpolicy", "SgrmAgent", "WindowsTrustedRT", "WindowsTrustedRTProxy",
            "iorate", "dam", "pcw", "volmgrx", "pdc", "CEA",
            "intelpep", "IntelPMT", "CLFS", "Fs_Rec", "Ntfs",
            "CimFS", "msisadrv", "pci", "vdrvroot", "partmgr", "volmgr",
            "mountmgr", "storahci", "stornvme", "EhStorTcgDrv",
            "fvevol", "rdyboost", "mup", "disk", "CLASSPNP",
            "crashdmp", "cdrom", "filecrypt", "tbs", "Null",
            "Beep", "dxgkrnl", "watchdog", "BasicDisplay", "BasicRender",
            "Npfs", "Msfs", "tdx", "TDI", "netbt", "afunix",
            "IKEEXT", "PolicyAgent", "BFE", "wfplwfs", "Dhcp",
            "Dnscache", "nsi", "Tcpip", "NDIS", "afd", "spaceport",
            // Microsoft system drivers commonly present on non-debloated Windows
            "UCPD", "MsSecFlt", "SgrmBroker", "bindflt", "wcifs",
            "storqosflt", "wcnfs", "CldFlt", "FileCrypt",
        };

        private static readonly string[] SuspiciousDriverPaths = new[]
        {
            @"\temp\", @"\tmp\", @"\downloads\", @"\appdata\",
            @"\users\", @"\desktop\", @"\documents\"
        };

        public BootIntegrityGuard(DetectionEngine de, ILogger<BootIntegrityGuard> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[BootIntegrityGuard] Started — monitoring boot configuration, EFI, and driver load order");

            await Task.Delay(30000, ct);
            await CaptureBaselineAsync();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    await CheckBcdIntegrityAsync();
                    await CheckBootDriversAsync();
                    await CheckEfiPartitionAsync();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[BootIntegrityGuard] Error");
                }
            }
        }

        private Task CaptureBaselineAsync()
        {
            try
            {
                _baselineBcd = CaptureBcdEntries();
                _baselineBootDrivers = CaptureBootDriverList();
                _baselineCaptured = true;
                _logger.LogInformation("[BootIntegrityGuard] Baseline: {Bcd} BCD entries, {Drv} boot drivers",
                    _baselineBcd.Count, _baselineBootDrivers.Count);
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[BootIntegrityGuard] Baseline capture failed"); }
            return Task.CompletedTask;
        }

        private async Task CheckBcdIntegrityAsync()
        {
            try
            {
                var current = CaptureBcdEntries();

                if (current.TryGetValue("testsigning", out var ts) &&
                    string.Equals(ts, "Yes", StringComparison.OrdinalIgnoreCase))
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Boot Integrity: Test Signing Enabled",
                        Evidence = "bcdedit testsigning=Yes — unsigned kernel drivers can load.",
                        Reasoning = "Rootkits enable test signing to load unsigned kernel components.",
                        Confidence = 0.95, Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string> { { "Setting", "testsigning" }, { "Value", "Yes" } }
                    });
                }

                if (current.TryGetValue("debug", out var dbg) &&
                    string.Equals(dbg, "Yes", StringComparison.OrdinalIgnoreCase))
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Boot Integrity: Kernel Debug Mode Enabled",
                        Evidence = "bcdedit debug=Yes — kernel debugger can attach.",
                        Reasoning = "Kernel debug mode allows remote kernel access. Rootkits enable this for persistent control.",
                        Confidence = 0.90, Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string> { { "Setting", "debug" }, { "Value", "Yes" } }
                    });
                }

                if (current.TryGetValue("nointegritychecks", out var nic) &&
                    string.Equals(nic, "Yes", StringComparison.OrdinalIgnoreCase))
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Boot Integrity: Integrity Checks Disabled",
                        Evidence = "bcdedit nointegritychecks=Yes — boot code integrity bypassed.",
                        Reasoning = "Disabling integrity checks allows tampered boot components to load unchallenged.",
                        Confidence = 0.95, Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string> { { "Setting", "nointegritychecks" }, { "Value", "Yes" } }
                    });
                }

                if (_baselineCaptured)
                {
                    foreach (var kvp in current)
                    {
                        if (!_baselineBcd.ContainsKey(kvp.Key))
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Boot Integrity: New BCD Entry",
                                Evidence = $"New boot config: {kvp.Key}={kvp.Value}",
                                Reasoning = "Bootkits add BCD entries for persistence.",
                                Confidence = 0.75, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                                Metadata = new Dictionary<string, string> { { "Entry", kvp.Key }, { "Value", kvp.Value } }
                            });
                        }
                        else if (_baselineBcd[kvp.Key] != kvp.Value)
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Boot Integrity: BCD Entry Modified",
                                Evidence = $"{kvp.Key}: '{_baselineBcd[kvp.Key]}' → '{kvp.Value}'",
                                Reasoning = "Boot configuration was modified at runtime — possible bootkit activity.",
                                Confidence = 0.80, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                                Metadata = new Dictionary<string, string> { { "Entry", kvp.Key }, { "Old", _baselineBcd[kvp.Key] }, { "New", kvp.Value } }
                            });
                        }
                    }
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[BootIntegrityGuard] BCD check error"); }
        }

        private async Task CheckBootDriversAsync()
        {
            try
            {
                if (!_baselineCaptured) return;
                var current = CaptureBootDriverList();
                var newDrivers = current.Except(_baselineBootDrivers, StringComparer.OrdinalIgnoreCase).ToList();

                foreach (var driver in newDrivers)
                {
                    if (TrustedBootDrivers.Contains(driver)) continue;

                    var imagePath = GetDriverImagePath(driver);
                    bool suspicious = !string.IsNullOrEmpty(imagePath) &&
                        SuspiciousDriverPaths.Any(p => imagePath.Contains(p, StringComparison.OrdinalIgnoreCase));

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Boot Integrity: New Boot Driver Registered",
                        Evidence = $"New boot driver '{driver}' — ImagePath: {imagePath ?? "unknown"}",
                        Reasoning = "Rootkits register kernel drivers for boot-start to load before security software.",
                        Confidence = suspicious ? 0.95 : 0.80,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string>
                        {
                            { "Driver", driver },
                            { "ImagePath", imagePath ?? "unknown" },
                            { "SuspiciousPath", suspicious.ToString() }
                        }
                    });
                }

                // Update baseline with current state so we only alert once per new driver
                if (newDrivers.Count > 0)
                {
                    _baselineBootDrivers = current;
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[BootIntegrityGuard] Driver check error"); }
        }

        private async Task CheckEfiPartitionAsync()
        {
            string? efiDir = null;
            bool mountedByUs = false;
            try
            {
                var result = FindEfiMountPoint();
                efiDir = result.Path;
                mountedByUs = result.MountedByUs;
                if (string.IsNullOrEmpty(efiDir)) return;

                // Check for bootmgfw.efi.bak — classic bootkit signature
                var bakPath = Path.Combine(efiDir, "EFI", "Microsoft", "Boot", "bootmgfw.efi.bak");
                if (File.Exists(bakPath))
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Boot Integrity: EFI Boot Manager Backup Found",
                        Evidence = $"File: {bakPath} — original boot manager may have been replaced.",
                        Reasoning = "EFI bootkits (BlackLotus, ESPecter) rename bootmgfw.efi to .bak and replace it.",
                        Confidence = 0.92, Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                        Metadata = new Dictionary<string, string> { { "File", bakPath } }
                    });
                }

                // Unknown .efi binaries in boot directory
                var bootDir = Path.Combine(efiDir, "EFI", "Microsoft", "Boot");
                if (Directory.Exists(bootDir))
                {
                    var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    { "bootmgfw.efi", "memtest.efi", "bootmgr.efi", "cdboot.efi",
                      "SecureBootRecovery.efi", "bootx64.efi", "bootaa64.efi",
                      "fwupx64.efi", "fwupaa64.efi", "mmx64.efi", "shimx64.efi" };

                    foreach (var file in Directory.GetFiles(bootDir, "*.efi"))
                    {
                        var name = Path.GetFileName(file);
                        if (!known.Contains(name) && !name.StartsWith("boot", StringComparison.OrdinalIgnoreCase))
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Boot Integrity: Unknown EFI Binary",
                                Evidence = $"Unknown EFI file: {file} ({new FileInfo(file).Length} bytes)",
                                Reasoning = "EFI bootkits place payloads in the Microsoft Boot directory to execute before the OS kernel.",
                                Confidence = 0.88, Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                                Metadata = new Dictionary<string, string> { { "File", file } }
                            });
                        }
                    }
                }

                // Unknown directories in EFI root
                var efiRoot = Path.Combine(efiDir, "EFI");
                if (Directory.Exists(efiRoot))
                {
                    var knownDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    { "Microsoft", "Boot", "HP", "Dell", "Lenovo", "ASUS", "Acer", "Intel", "OEM", "ubuntu", "grub", "refind" };

                    foreach (var dir in Directory.GetDirectories(efiRoot))
                    {
                        var dirName = Path.GetFileName(dir);
                        if (!knownDirs.Contains(dirName))
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Boot Integrity: Unknown EFI Directory",
                                Evidence = $"Unknown EFI partition directory: {dir}",
                                Reasoning = "Advanced bootkits create directories in ESP to store payloads.",
                                Confidence = 0.70, Tier = DetectionTier.Tier2Indicator,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM", ProcessId = 0, SignalType = SignalType.AntiTamper,
                                Metadata = new Dictionary<string, string> { { "Directory", dir } }
                            });
                        }
                    }
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[BootIntegrityGuard] EFI check error"); }
            finally
            {
                if (mountedByUs && efiDir != null)
                {
                    UnmountEfiVolume(efiDir);
                }
            }
        }

        private static Dictionary<string, string> CaptureBcdEntries()
        {
            var entries = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                var psi = new ProcessStartInfo("bcdedit.exe", "/enum all")
                { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true };
                using var proc = Process.Start(psi);
                if (proc == null) return entries;
                var output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(10000);

                foreach (var line in output.Split('\n'))
                {
                    var trimmed = line.Trim();
                    var idx = trimmed.IndexOf(' ');
                    if (idx > 0)
                    {
                        var key = trimmed[..idx].Trim();
                        var val = trimmed[(idx + 1)..].Trim();
                        if (!string.IsNullOrEmpty(key))
                            entries.TryAdd(key, val);
                    }
                }
            }
            catch { }
            return entries;
        }

        private static List<string> CaptureBootDriverList()
        {
            var drivers = new List<string>();
            try
            {
                using var svcKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                if (svcKey == null) return drivers;

                foreach (var name in svcKey.GetSubKeyNames())
                {
                    try
                    {
                        using var dk = svcKey.OpenSubKey(name);
                        if (dk == null) continue;
                        var start = dk.GetValue("Start");
                        var type = dk.GetValue("Type");
                        if (start is int s && type is int t && s <= 1 && (t == 1 || t == 2))
                            drivers.Add(name);
                    }
                    catch { }
                }
            }
            catch { }
            return drivers;
        }

        private static string? GetDriverImagePath(string driverName)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{driverName}");
                return key?.GetValue("ImagePath") as string;
            }
            catch { return null; }
        }

        private static (string? Path, bool MountedByUs) FindEfiMountPoint()
        {
            try
            {
                // Check all drive letters A-Z for an already-mounted EFI partition
                for (char c = 'A'; c <= 'Z'; c++)
                {
                    var candidate = $@"{c}:\";
                    try
                    {
                        if (Directory.Exists(Path.Combine(candidate, "EFI")))
                            return (candidate, false);
                    }
                    catch { }
                }

                // Find a free drive letter to mount onto — avoid any letter already in use
                var usedLetters = new HashSet<char>(
                    DriveInfo.GetDrives()
                        .Where(d => d.Name.Length >= 1)
                        .Select(d => char.ToUpperInvariant(d.Name[0])));

                // Prefer letters near the end of the alphabet that are unlikely to conflict
                char mountLetter = '\0';
                foreach (char preferred in "ZYXWVUTSRQPONMLKJIHGFEDCBA")
                {
                    if (!usedLetters.Contains(preferred))
                    {
                        mountLetter = preferred;
                        break;
                    }
                }

                if (mountLetter == '\0') return (null, false); // No free letter

                var mountPath = $@"{mountLetter}:\";
                var psi = new ProcessStartInfo("mountvol.exe", $@"{mountPath} /S")
                { CreateNoWindow = true, UseShellExecute = false };
                using var proc = Process.Start(psi);
                proc?.WaitForExit(5000);

                if (Directory.Exists(Path.Combine(mountPath, "EFI")))
                    return (mountPath, true);

                // Mount failed or no EFI folder — clean up immediately
                UnmountEfiVolume(mountPath);
            }
            catch { }
            return (null, false);
        }

        private static void UnmountEfiVolume(string? mountPath = null)
        {
            // If no path given, try to unmount S:\ for backward compat
            var target = mountPath ?? @"S:\";
            try
            {
                var psi = new ProcessStartInfo("mountvol.exe", $@"{target} /D")
                { CreateNoWindow = true, UseShellExecute = false };
                using var proc = Process.Start(psi);
                proc?.WaitForExit(5000);
            }
            catch { }
        }
    }


    // ──────────────────────────────────────────────
    // WMI Provider Integrity Monitor — detects malicious WMI provider DLLs (v1.6.6)
    // ──────────────────────────────────────────────
    // A malicious WMI provider DLL runs inside WmiPrvSE.exe (legitimate SYSTEM process)
    // and can intercept/modify WMI query results (fake thermals, throttle power settings)
    // or execute arbitrary code on any WMI query to its namespace — without any visible
    // process, autorun entry, scheduled task, or WMI event subscription.
    //
    // This monitor:
    //   1. Enumerates all __Win32Provider objects across WMI namespaces
    //   2. Resolves CLSID → InprocServer32 → DLL path
    //   3. Validates Authenticode signatures (unsigned in sensitive namespace = Tier1)
    //   4. Baselines known providers at startup; alerts on new providers at runtime
    //   5. Scans WmiPrvSE.exe loaded modules for non-system DLLs
    //   6. Checks for MOF auto-recovery persistence
    // ──────────────────────────────────────────────
    public sealed class WmiProviderIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WmiProviderIntegrityMonitor> _logger;

        // Baseline: provider name → resolved DLL path (from first scan)
        private readonly Dictionary<string, WmiProviderInfo> _baselineProviders = new(StringComparer.OrdinalIgnoreCase);
        private bool _baselineEstablished;

        // Sensitive WMI namespaces — unsigned providers here are high-confidence threats
        // (power management, thermal, Intel DTT, hardware monitoring)
        private static readonly HashSet<string> SensitiveNamespaces = new(StringComparer.OrdinalIgnoreCase)
        {
            @"root\wmi",
            @"root\intel",
            @"root\intel\dtt",
            @"root\cimv2\power",
            @"root\cimv2\thermal",
            @"root\hardware",
            @"root\microsoft\windows\storage",
            @"root\standardcimv2",
        };

        // Known legitimate non-Microsoft providers that will be unsigned or third-party signed
        // (GPU drivers, OEM tools, etc.) — suppress false positives
        private static readonly HashSet<string> KnownThirdPartyProviders = new(StringComparer.OrdinalIgnoreCase)
        {
            "NVDisplay.ContainerLocalSystem",   // NVIDIA
            "nvloggr",                          // NVIDIA logging
            "RmProvider",                       // NVIDIA resource manager
            "IntelProv",                        // Intel chipset
            "AmdProv",                          // AMD
            "ASUSWMIProvider",                  // ASUS motherboard
            "MSIWmiProvider",                   // MSI motherboard
            "GigabyteProvider",                 // Gigabyte motherboard
            "RealtekProv",                      // Realtek audio/NIC
            "WmiPerfClass",                     // Windows perf counters (catalog-signed)
            "CIMWin32",                         // Core Windows provider (catalog-signed)
            "Win32ClockProvider",               // Windows time provider
            "StandardCimv2",                    // Windows networking provider
        };

        // Scan interval: 5 minutes (balances detection speed vs performance)
        private static readonly TimeSpan ScanInterval = TimeSpan.FromMinutes(5);

        public WmiProviderIntegrityMonitor(DetectionEngine de, ILogger<WmiProviderIntegrityMonitor> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WmiProviderIntegrityMonitor] Started — scanning WMI provider DLLs for integrity");

            // Initial delay to let system stabilize after boot
            await Task.Delay(15000, ct);

            // Establish baseline
            var providers = EnumerateAllProviders();
            foreach (var p in providers)
                _baselineProviders[p.ProviderKey] = p;
            _baselineEstablished = true;

            _logger.LogInformation("[WmiProviderIntegrityMonitor] Baseline established: {Count} providers", _baselineProviders.Count);

            // Scan baseline for existing suspicious providers (pre-installed rootkit)
            await ScanForSuspiciousProvidersAsync(_baselineProviders.Values, isBaseline: _baselineEstablished, ct);

            // Periodic scanning loop
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);

                    // Re-enumerate and check for new providers
                    var current = EnumerateAllProviders();
                    var newProviders = new List<WmiProviderInfo>();

                    foreach (var p in current)
                    {
                        if (!_baselineProviders.ContainsKey(p.ProviderKey))
                        {
                            newProviders.Add(p);
                            _baselineProviders[p.ProviderKey] = p;
                        }
                    }

                    // Alert on new providers
                    if (newProviders.Count > 0)
                    {
                        await ScanForSuspiciousProvidersAsync(newProviders, isBaseline: false, ct);
                    }

                    // Scan WmiPrvSE.exe loaded modules
                    await ScanWmiPrvSeModulesAsync(ct);

                    // Check MOF auto-recovery
                    await CheckMofAutoRecoveryAsync(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[WmiProviderIntegrityMonitor] Error in scan loop"); }
            }
        }

        /// <summary>
        /// Enumerates __Win32Provider objects across common WMI namespaces.
        /// Resolves each provider's CLSID to its InprocServer32 DLL path.
        /// </summary>
        private List<WmiProviderInfo> EnumerateAllProviders()
        {
            var results = new List<WmiProviderInfo>();
            var namespacesToScan = GetWmiNamespaces();

            foreach (var ns in namespacesToScan)
            {
                try
                {
                    using var searcher = new ManagementObjectSearcher(ns, "SELECT * FROM __Win32Provider");
                    searcher.Options.Timeout = TimeSpan.FromSeconds(10);

                    foreach (ManagementObject obj in searcher.Get())
                    {
                        try
                        {
                            var name = obj["Name"]?.ToString() ?? "";
                            var clsid = obj["CLSID"]?.ToString() ?? "";

                            if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(clsid))
                                continue;

                            var dllPath = ResolveCLSIDtoDll(clsid);

                            results.Add(new WmiProviderInfo
                            {
                                Name = name,
                                Namespace = ns,
                                CLSID = clsid,
                                DllPath = dllPath,
                                ProviderKey = $"{ns}\\{name}\\{clsid}"
                            });
                        }
                        catch { }
                    }
                }
                catch { } // Namespace may not exist or be inaccessible
            }

            return results;
        }

        /// <summary>
        /// Gets all WMI namespaces to scan by recursively enumerating from root.
        /// Falls back to a hardcoded list of common namespaces if enumeration fails.
        /// </summary>
        private List<string> GetWmiNamespaces()
        {
            var namespaces = new List<string>();
            try
            {
                // Start with root and enumerate child namespaces
                EnumerateNamespacesRecursive(@"root", namespaces, depth: 0, maxDepth: 3);
            }
            catch
            {
                // Fallback: common namespaces where malicious providers would register
                namespaces.AddRange(new[]
                {
                    @"root\cimv2",
                    @"root\wmi",
                    @"root\default",
                    @"root\subscription",
                    @"root\standardcimv2",
                    @"root\microsoft\windows\storage",
                    @"root\intel",
                });
            }

            return namespaces;
        }

        private void EnumerateNamespacesRecursive(string parentNs, List<string> results, int depth, int maxDepth)
        {
            results.Add(parentNs);
            if (depth >= maxDepth) return;

            try
            {
                using var searcher = new ManagementObjectSearcher(parentNs, "SELECT * FROM __NAMESPACE");
                searcher.Options.Timeout = TimeSpan.FromSeconds(5);

                foreach (ManagementObject obj in searcher.Get())
                {
                    var childName = obj["Name"]?.ToString();
                    if (!string.IsNullOrEmpty(childName))
                    {
                        var childPath = $@"{parentNs}\{childName}";
                        EnumerateNamespacesRecursive(childPath, results, depth + 1, maxDepth);
                    }
                }
            }
            catch { } // Some namespaces deny enumeration — skip silently
        }

        /// <summary>
        /// Resolves a COM CLSID to its InprocServer32 DLL path via the registry.
        /// </summary>
        private static string? ResolveCLSIDtoDll(string clsid)
        {
            if (string.IsNullOrEmpty(clsid)) return null;

            // Normalize CLSID format
            if (!clsid.StartsWith("{")) clsid = "{" + clsid + "}";

            try
            {
                // Check 64-bit registry view first
                using var key = Registry.LocalMachine.OpenSubKey(
                    $@"SOFTWARE\Classes\CLSID\{clsid}\InprocServer32", false);
                if (key != null)
                {
                    var dll = key.GetValue("")?.ToString() ?? key.GetValue("(Default)")?.ToString();
                    if (!string.IsNullOrEmpty(dll))
                        return Environment.ExpandEnvironmentVariables(dll);
                }

                // Check WOW64 (32-bit) registry view
                using var wow64Key = Registry.LocalMachine.OpenSubKey(
                    $@"SOFTWARE\WOW6432Node\Classes\CLSID\{clsid}\InprocServer32", false);
                if (wow64Key != null)
                {
                    var dll = wow64Key.GetValue("")?.ToString() ?? wow64Key.GetValue("(Default)")?.ToString();
                    if (!string.IsNullOrEmpty(dll))
                        return Environment.ExpandEnvironmentVariables(dll);
                }
            }
            catch { }

            return null;
        }

        /// <summary>
        /// Analyzes providers for suspicious characteristics:
        /// - Unsigned DLL in a sensitive namespace (power, thermal, Intel) → Tier1 (0.88)
        /// - Unsigned DLL in non-system path → Tier1 (0.80)
        /// - New provider added at runtime (not in baseline) → Tier1 (0.82)
        /// - Unsigned DLL in standard namespace → Tier2 (0.65)
        /// </summary>
        private async Task ScanForSuspiciousProvidersAsync(
            IEnumerable<WmiProviderInfo> providers, bool isBaseline, CancellationToken ct)
        {
            foreach (var provider in providers)
            {
                if (ct.IsCancellationRequested) break;

                // Skip providers with no resolved DLL (out-of-process or missing)
                if (string.IsNullOrEmpty(provider.DllPath)) continue;

                // Skip known third-party providers (GPU drivers, OEM tools)
                if (KnownThirdPartyProviders.Contains(provider.Name)) continue;

                // Check if the DLL exists on disk
                if (!File.Exists(provider.DllPath)) continue;

                // Check if DLL is in a system-protected path
                bool isSystemPath = IsSystemProtectedPath(provider.DllPath);

                // Verify Authenticode signature
                bool isSigned = SecurityValidation.VerifyAuthenticodeSignature(provider.DllPath);

                // Determine if namespace is sensitive (power/thermal/hardware)
                bool isSensitiveNs = IsSensitiveNamespace(provider.Namespace);

                // Extract publisher for logging
                string publisher = isSigned ? GetSignerPublisher(provider.DllPath) : "UNSIGNED";

                // Decision matrix:
                if (!isSigned && isSensitiveNs)
                {
                    // HIGHEST THREAT: Unsigned DLL in power/thermal/Intel namespace
                    // This is the exact pattern a performance-throttling rootkit would use
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "WMI Provider Integrity: Unsigned Provider in Sensitive Namespace",
                        Evidence = $"Unsigned WMI provider DLL in sensitive namespace. " +
                                   $"Provider: '{provider.Name}', Namespace: '{provider.Namespace}', " +
                                   $"CLSID: {provider.CLSID}, DLL: '{provider.DllPath}', " +
                                   $"NewAtRuntime: {!isBaseline}",
                        Reasoning = "An unsigned DLL is registered as a WMI provider in a power, thermal, or hardware " +
                                    "namespace. This is the exact technique used by performance-throttling rootkits that " +
                                    "intercept WMI queries to fake thermal readings or modify power settings. The DLL " +
                                    "executes inside WmiPrvSE.exe (SYSTEM) with no visible process or autorun entry.",
                        Confidence = 0.88,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcess,
                        ProcessName = "WmiPrvSE.exe",
                        ProcessId = 0
                    });
                    _logger.LogWarning("[WmiProviderIntegrityMonitor] ALERT: Unsigned provider in sensitive namespace: " +
                        "{Name} @ {Namespace} → {Dll}", provider.Name, provider.Namespace, provider.DllPath);
                }
                else if (!isSigned && !isSystemPath)
                {
                    // HIGH THREAT: Unsigned DLL outside system paths (staging/temp/user dirs)
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "WMI Provider Integrity: Unsigned Provider from Non-System Path",
                        Evidence = $"Unsigned WMI provider DLL loaded from non-system path. " +
                                   $"Provider: '{provider.Name}', Namespace: '{provider.Namespace}', " +
                                   $"CLSID: {provider.CLSID}, DLL: '{provider.DllPath}', Publisher: {publisher}",
                        Reasoning = "A WMI provider DLL that is unsigned and located outside of Windows system directories " +
                                    "was detected. Legitimate providers are typically signed and installed under System32 or " +
                                    "Program Files. This pattern matches malicious WMI provider persistence (T1546.003 variant).",
                        Confidence = isBaseline ? 0.75 : 0.82,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "WmiPrvSE.exe",
                        ProcessId = 0
                    });
                    _logger.LogWarning("[WmiProviderIntegrityMonitor] Suspicious unsigned provider: {Name} → {Dll}",
                        provider.Name, provider.DllPath);
                }
                else if (!isBaseline && !isSigned)
                {
                    // MEDIUM: New unsigned provider appeared at runtime (even in system path)
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "WMI Provider Integrity: New Unsigned Provider at Runtime",
                        Evidence = $"New unsigned WMI provider registered since startup. " +
                                   $"Provider: '{provider.Name}', Namespace: '{provider.Namespace}', " +
                                   $"CLSID: {provider.CLSID}, DLL: '{provider.DllPath}'",
                        Reasoning = "A new WMI provider was registered after Sentinel baseline was established. " +
                                    "Runtime provider registration is uncommon outside of software installation and " +
                                    "may indicate a rootkit installing a persistent WMI provider.",
                        Confidence = 0.70,
                        Tier = DetectionTier.Tier2Indicator,
                        ProcessName = "WmiPrvSE.exe",
                        ProcessId = 0
                    });
                }
            }
        }

        /// <summary>
        /// Scans all WmiPrvSE.exe instances for loaded DLLs outside system directories.
        /// A legitimate WmiPrvSE should only load DLLs from System32, WinSxS, and
        /// registered provider paths (Program Files). Non-system DLLs indicate injection
        /// or a malicious provider that sideloaded additional components.
        /// </summary>
        private async Task ScanWmiPrvSeModulesAsync(CancellationToken ct)
        {
            try
            {
                var wmiProcs = Process.GetProcessesByName("WmiPrvSE");
                foreach (var proc in wmiProcs)
                {
                    try
                    {
                        if (ct.IsCancellationRequested) break;

                        foreach (ProcessModule module in proc.Modules)
                        {
                            try
                            {
                                var modulePath = module.FileName;
                                if (string.IsNullOrEmpty(modulePath)) continue;

                                // Skip known-good system paths
                                if (IsSystemProtectedPath(modulePath)) continue;

                                // Skip known Program Files paths (legitimate third-party providers)
                                if (IsInProgramFiles(modulePath)) continue;

                                // Non-system DLL loaded in WmiPrvSE — suspicious
                                bool isSigned = SecurityValidation.VerifyAuthenticodeSignature(modulePath);
                                if (!isSigned)
                                {
                                    await _detectionEngine.EmitAsync(new DetectionEvent
                                    {
                                        RuleName = "WMI Provider Integrity: Suspicious Module in WmiPrvSE",
                                        Evidence = $"Unsigned non-system DLL loaded in WmiPrvSE.exe (PID {proc.Id}): '{modulePath}'",
                                        Reasoning = "WmiPrvSE.exe has loaded an unsigned DLL from a non-system path. " +
                                                    "This process hosts WMI providers and should only load system DLLs and " +
                                                    "registered provider binaries. An unsigned module may indicate a " +
                                                    "malicious WMI provider or DLL injection into the WMI host.",
                                        Confidence = 0.85,
                                        Tier = DetectionTier.Tier1Behavioral,
                                        AuthorizedResponse = ResponseAction.LogOnly,
                                        ProcessName = "WmiPrvSE.exe",
                                        ProcessId = proc.Id
                                    });
                                    _logger.LogWarning("[WmiProviderIntegrityMonitor] Unsigned module in WmiPrvSE PID {Pid}: {Path}",
                                        proc.Id, modulePath);
                                }
                            }
                            catch { } // Module access may fail for protected modules
                        }
                    }
                    catch { } // Process may exit during enumeration
                    finally { proc.Dispose(); }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[WmiProviderIntegrityMonitor] Error scanning WmiPrvSE modules");
            }
        }

        /// <summary>
        /// Checks the MOF auto-recovery registry key for non-Windows MOF files.
        /// MOF auto-recovery is a legacy persistence mechanism that auto-compiles
        /// MOF files into WMI on repository rebuild — survives WMI reset.
        /// </summary>
        private async Task CheckMofAutoRecoveryAsync(CancellationToken ct)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\WBEM\CIMOM", false);
                if (key == null) return;

                var mofs = key.GetValue("Autorecover MOFs") as string[];
                if (mofs == null || mofs.Length == 0) return;

                foreach (var mof in mofs)
                {
                    if (ct.IsCancellationRequested) break;
                    if (string.IsNullOrWhiteSpace(mof)) continue;

                    // System MOFs under %SystemRoot%\System32\wbem are legitimate
                    var expanded = Environment.ExpandEnvironmentVariables(mof);
                    if (IsSystemProtectedPath(expanded)) continue;

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "WMI Provider Integrity: Suspicious MOF Auto-Recovery Entry",
                        Evidence = $"Non-system MOF file in auto-recovery list: '{expanded}'",
                        Reasoning = "A MOF file outside of the Windows system directory is registered for " +
                                    "WMI auto-recovery. This legacy mechanism auto-compiles MOF definitions " +
                                    "into the WMI repository on rebuild, providing rootkit-level persistence " +
                                    "that survives WMI repository resets.",
                        Confidence = 0.80,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM",
                        ProcessId = 0
                    });
                    _logger.LogWarning("[WmiProviderIntegrityMonitor] Suspicious MOF auto-recovery: {Path}", expanded);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[WmiProviderIntegrityMonitor] Error checking MOF auto-recovery");
            }
        }

        /// <summary>
        /// Checks if a path is under Windows system-protected directories.
        /// </summary>
        private static bool IsSystemProtectedPath(string path)
        {
            var normalized = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar);
            var sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var sys32 = Path.Combine(sysRoot, "System32");
            var sysWow = Path.Combine(sysRoot, "SysWOW64");
            var winsxs = Path.Combine(sysRoot, "WinSxS");

            return normalized.StartsWith(sys32, StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith(sysWow, StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith(winsxs, StringComparison.OrdinalIgnoreCase) ||
                   normalized.StartsWith(sysRoot + @"\assembly", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Checks if a path is under Program Files (legitimate third-party install location).
        /// </summary>
        private static bool IsInProgramFiles(string path)
        {
            var normalized = Path.GetFullPath(path);
            var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

            return normalized.StartsWith(pf, StringComparison.OrdinalIgnoreCase) ||
                   (!string.IsNullOrEmpty(pf86) && normalized.StartsWith(pf86, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Determines if a namespace is in the sensitive list (power/thermal/hardware).
        /// </summary>
        private static bool IsSensitiveNamespace(string ns)
        {
            foreach (var sensitive in SensitiveNamespaces)
            {
                if (ns.StartsWith(sensitive, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Extracts the publisher/signer subject from a signed binary.
        /// Returns "Unknown" if the cert cannot be read.
        /// </summary>
        private static string GetSignerPublisher(string filePath)
        {
            try
            {
#pragma warning disable SYSLIB0057
                var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
                return cert?.Subject ?? "Unknown";
            }
            catch { return "Unknown"; }
        }

        /// <summary>
        /// Tracks information about a WMI provider registration.
        /// </summary>
        private sealed class WmiProviderInfo
        {
            public string Name { get; set; } = "";
            public string Namespace { get; set; } = "";
            public string CLSID { get; set; } = "";
            public string? DllPath { get; set; }
            /// <summary>Unique key: namespace\name\clsid for deduplication.</summary>
            public string ProviderKey { get; set; } = "";
        }
    }


}
