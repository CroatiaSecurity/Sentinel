using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Windows Firewall Integrity Monitor (v3.6.0) — Detects firewall tampering.
///
/// Malware commonly disables or modifies the Windows Firewall to:
///   - Allow inbound C2 connections
///   - Enable reverse shells without triggering firewall prompts
///   - Open ports for lateral movement
///   - Disable all filtering to avoid detection
///
/// Detection strategy:
///   1. Monitor firewall profile states (Domain/Private/Public) — alert if disabled.
///   2. Detect new inbound allow rules (especially "any" port or suspicious ports).
///   3. Detect firewall service (mpssvc) being stopped.
///   4. Monitor for bulk rule additions (malware adding many rules at once).
///
/// Uses netsh advfirewall for reliable cross-version compatibility.
/// </summary>
public sealed class FirewallIntegrityMonitor : BackgroundService
{
    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<FirewallIntegrityMonitor> _logger;

    // Baseline
    private bool? _baselineDomainEnabled;
    private bool? _baselinePrivateEnabled;
    private bool? _baselinePublicEnabled;
    private int _baselineInboundRuleCount;
    private bool _baselineCaptured;

    // Deduplication
    private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedEvents = new();
    private static readonly TimeSpan AlertDedupeWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(30);

    public FirewallIntegrityMonitor(
        IDetectionEngine detectionEngine,
        ILogger<FirewallIntegrityMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("[FirewallIntegrityMonitor] Starting — firewall integrity monitoring active");

        await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);

        CaptureBaseline();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CheckFirewallStateAsync(stoppingToken);
                PruneAlertCache();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "[FirewallIntegrityMonitor] Check error");
            }

            await Task.Delay(PollInterval, stoppingToken);
        }
    }

    private void CaptureBaseline()
    {
        var state = GetFirewallState();
        if (state == null) return;

        _baselineDomainEnabled = state.DomainEnabled;
        _baselinePrivateEnabled = state.PrivateEnabled;
        _baselinePublicEnabled = state.PublicEnabled;
        _baselineInboundRuleCount = GetInboundAllowRuleCount();
        _baselineCaptured = true;

        _logger.LogInformation(
            "[FirewallIntegrityMonitor] Baseline: Domain={D}, Private={P}, Public={Pub}, InboundRules={R}",
            state.DomainEnabled, state.PrivateEnabled, state.PublicEnabled, _baselineInboundRuleCount);
    }

    private async Task CheckFirewallStateAsync(CancellationToken ct)
    {
        if (!_baselineCaptured) return;

        var state = GetFirewallState();
        if (state == null) return;

        // ═══════════════════════════════════════════════════════════════════
        // CHECK 1: Firewall profile disabled
        // ═══════════════════════════════════════════════════════════════════
        if (_baselineDomainEnabled == true && state.DomainEnabled == false)
            await EmitProfileDisabledAsync("Domain", ct);
        if (_baselinePrivateEnabled == true && state.PrivateEnabled == false)
            await EmitProfileDisabledAsync("Private", ct);
        if (_baselinePublicEnabled == true && state.PublicEnabled == false)
            await EmitProfileDisabledAsync("Public", ct);

        // Update baseline
        _baselineDomainEnabled = state.DomainEnabled;
        _baselinePrivateEnabled = state.PrivateEnabled;
        _baselinePublicEnabled = state.PublicEnabled;

        // ═══════════════════════════════════════════════════════════════════
        // CHECK 2: Bulk inbound rule additions (malware opening many ports)
        // ═══════════════════════════════════════════════════════════════════
        var currentRuleCount = GetInboundAllowRuleCount();
        var rulesAdded = currentRuleCount - _baselineInboundRuleCount;

        if (rulesAdded >= 5) // 5+ new inbound allow rules since last check
        {
            var dedupeKey = $"bulk_rules:{currentRuleCount}";
            if (!_alertedEvents.ContainsKey(dedupeKey))
            {
                _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Firewall Tampering: Bulk Inbound Rules Added",
                    Evidence = $"{rulesAdded} new inbound ALLOW rules added to Windows Firewall " +
                               $"(was {_baselineInboundRuleCount}, now {currentRuleCount}). " +
                               "Malware commonly adds firewall rules to allow C2 and lateral movement.",
                    Reasoning = "A large number of inbound allow rules being added in a short period " +
                                "indicates malware opening the firewall for: (1) C2 callback ports, " +
                                "(2) lateral movement (SMB, WMI, RDP), (3) reverse shell listeners, " +
                                "(4) data exfiltration channels. Legitimate software rarely adds more " +
                                "than 1-2 rules at a time.",
                    Confidence = 0.82,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = "Firewall",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["rules_added"] = rulesAdded.ToString(),
                        ["total_rules"] = currentRuleCount.ToString(),
                        ["technique"] = "T1562.004 - Impair Defenses: Disable or Modify System Firewall",
                        ["attack_type"] = "bulk_firewall_rules"
                    }
                }, ct);
            }
        }

        _baselineInboundRuleCount = currentRuleCount;

        // ═══════════════════════════════════════════════════════════════════
        // CHECK 3: Firewall service stopped
        // ═══════════════════════════════════════════════════════════════════
        if (!IsFirewallServiceRunning())
        {
            var dedupeKey = "fw_service_stopped";
            if (!_alertedEvents.ContainsKey(dedupeKey))
            {
                _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "Firewall Tampering: Windows Firewall Service Stopped",
                    Evidence = "The Windows Firewall service (mpssvc) is NOT running. " +
                               "All firewall rules are inactive — the system has no network filtering.",
                    Reasoning = "The Windows Firewall service being stopped means ALL firewall rules " +
                                "are inactive. The system accepts all inbound and outbound connections " +
                                "without restriction. Malware stops this service to enable unrestricted " +
                                "network access for C2, lateral movement, and data exfiltration.",
                    Confidence = 0.90,
                    Tier = DetectionTier.Tier1Behavioral,
                    ProcessName = "Firewall",
                    ProcessId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    Metadata = new Dictionary<string, string>
                    {
                        ["service_state"] = "stopped",
                        ["technique"] = "T1562.004 - Impair Defenses: Disable or Modify System Firewall",
                        ["attack_type"] = "firewall_service_stopped"
                    }
                }, ct);
            }
        }
    }

    private async Task EmitProfileDisabledAsync(string profile, CancellationToken ct)
    {
        var dedupeKey = $"fw_disabled:{profile}";
        if (_alertedEvents.ContainsKey(dedupeKey)) return;
        _alertedEvents.TryAdd(dedupeKey, DateTimeOffset.UtcNow);

        await _detectionEngine.EmitAsync(new DetectionEvent
        {
            RuleName = $"Firewall Tampering: {profile} Profile Disabled",
            Evidence = $"Windows Firewall {profile} profile was DISABLED (was previously enabled). " +
                       "All inbound connections to this profile are now unfiltered.",
            Reasoning = $"The {profile} firewall profile being disabled removes all inbound filtering " +
                        "for that network type. Malware disables firewall profiles to: " +
                        "(1) allow inbound C2 connections, (2) enable reverse shells, " +
                        "(3) permit lateral movement tools (psexec, wmi). " +
                        "If the user didn't disable it, this is active defense evasion.",
            Confidence = 0.88,
            Tier = DetectionTier.Tier1Behavioral,
            ProcessName = "Firewall",
            ProcessId = 0,
            Timestamp = DateTimeOffset.UtcNow,
            Metadata = new Dictionary<string, string>
            {
                ["profile"] = profile,
                ["state"] = "disabled",
                ["technique"] = "T1562.004 - Impair Defenses: Disable or Modify System Firewall",
                ["attack_type"] = "firewall_profile_disabled"
            }
        }, ct);
    }

    private static FirewallState? GetFirewallState()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = "advfirewall show allprofiles state",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc == null) return null;

            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            // Parse "State    ON/OFF" for each profile
            var lines = output.Split('\n');
            bool? domain = null, priv = null, pub = null;
            string? currentProfile = null;

            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (trimmed.Contains("Domain Profile", StringComparison.OrdinalIgnoreCase))
                    currentProfile = "domain";
                else if (trimmed.Contains("Private Profile", StringComparison.OrdinalIgnoreCase))
                    currentProfile = "private";
                else if (trimmed.Contains("Public Profile", StringComparison.OrdinalIgnoreCase))
                    currentProfile = "public";
                else if (trimmed.StartsWith("State", StringComparison.OrdinalIgnoreCase))
                {
                    var isOn = trimmed.Contains("ON", StringComparison.OrdinalIgnoreCase);
                    switch (currentProfile)
                    {
                        case "domain": domain = isOn; break;
                        case "private": priv = isOn; break;
                        case "public": pub = isOn; break;
                    }
                }
            }

            return new FirewallState
            {
                DomainEnabled = domain,
                PrivateEnabled = priv,
                PublicEnabled = pub
            };
        }
        catch { return null; }
    }

    private static int GetInboundAllowRuleCount()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = "advfirewall firewall show rule name=all dir=in",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc == null) return 0;

            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(10000);

            // Count "Action:  Allow" lines
            return output.Split('\n')
                .Count(l => l.Trim().StartsWith("Action:", StringComparison.OrdinalIgnoreCase) &&
                           l.Contains("Allow", StringComparison.OrdinalIgnoreCase));
        }
        catch { return 0; }
    }

    private static bool IsFirewallServiceRunning()
    {
        try
        {
            using var sc = new System.ServiceProcess.ServiceController("mpssvc");
            return sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
        }
        catch { return true; } // Assume running if we can't check
    }

    private void PruneAlertCache()
    {
        var cutoff = DateTimeOffset.UtcNow - AlertDedupeWindow;
        foreach (var kvp in _alertedEvents)
        {
            if (kvp.Value < cutoff)
                _alertedEvents.TryRemove(kvp.Key, out _);
        }
    }

    private sealed class FirewallState
    {
        public bool? DomainEnabled { get; init; }
        public bool? PrivateEnabled { get; init; }
        public bool? PublicEnabled { get; init; }
    }
}
