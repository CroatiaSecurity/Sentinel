using System;
using System.Collections.Generic;

namespace Sentinel.Core
{
    public enum DetectionTier
    {
        Tier1Behavioral,
        Tier2Indicator
    }

    public enum ResponseAction
    {
        LogOnly,
        NetworkIsolate,
        RemoveCert,
        KillProcess,
        KillProcessTree,
        Quarantine,
        QuarantineAndKill,
        RemoveCertAndKillAdder,
        RemoveRegistryEntry,
        DismountVolume
    }

    public enum SignalType
    {
        Generic,
        LsassAccess,
        AmsiTampering,
        EtwTampering,
        Ransomware,
        ReverseShell,
        NetworkC2,
        CredentialTheft,
        ProcessInjection,
        SuspiciousProcess,
        AntiTamper,
        SecurityEvasion,
        PhantomKeystroke
    }

    public class CveShieldConfig
    {
        public bool Enabled { get; set; } = true;
        public string FeedUrl { get; set; } = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
        public int PollIntervalHours { get; set; } = 4;
        public string? CustomFeedPath { get; set; } // Local fallback JSON for offline testing
    }

    public class SentinelConfig
    {
        public bool ActiveResponse { get; set; } = true;
        public string? LogPath { get; set; }
        public string? WatchPath { get; set; }
        /// <summary>
        /// Explicit allowlist of Cast device IPs on the LAN.
        /// v1.8.3: Empty = observe-only (log Cast traffic, do not firewall-block).
        /// Non-empty = enforce allowlist (block LAN Cast IPs not listed).
        /// Post-incident hosts that need zero-trust Cast should list only known devices
        /// (or use a deliberate block after a phantom Cast IP is confirmed).
        /// </summary>
        public string[] TrustedCastDevices { get; set; } = Array.Empty<string>();

        // Dynamic polling intervals (configurable)
        public int DnsPollIntervalSeconds { get; set; } = 15;
        public int RouteTableScanIntervalSeconds { get; set; } = 15;
        public int RawDiskScanIntervalSeconds { get; set; } = 20;
        public int AntiTamperTimingTickMs { get; set; } = 2000;
        public int AntiTamperIntegrityTickMs { get; set; } = 10000;

        /// <summary>
        /// v1.6.0: Maximum process kill/quarantine-kill actions per rolling 60 seconds.
        /// Prevents weaponized false-positive storms. NetworkIsolate is not counted.
        /// 0 = unlimited (not recommended).
        /// </summary>
        public int MaxKillsPerMinute { get; set; } = 15;

        /// <summary>
        /// v1.6.1: Maximum new NetworkIsolate firewall targets per rolling 60 seconds.
        /// Prevents isolate-storm DoS / CDN collateral from decoy beacons.
        /// 0 = unlimited (not recommended).
        /// </summary>
        public int MaxNetworkIsolatesPerMinute { get; set; } = 10;

        /// <summary>
        /// v1.6.0: When true (default), ActiveResponse=false at startup or in appsettings
        /// is treated as tampering: force re-enable + Tier1 alert.
        /// Set false only for intentional observation/lab mode.
        /// </summary>
        public bool EnforceActiveResponse { get; set; } = true;

        /// <summary>
        /// v1.8.3: When true, ThreatIntelFeedBlocker pre-creates Windows Firewall block rules
        /// for every feed IP/CIDR. Default <c>false</c> — observe connections to listed IPs
        /// and only act reactively (NetworkIsolate on live hit when ActiveResponse is on).
        /// Pre-blocking thousands of ranges breaks legitimate TLS/OCSP/CDN traffic.
        /// </summary>
        public bool ThreatIntelProactiveFirewall { get; set; } = false;

        /// <summary>
        /// v1.8.3: When true, permanently block Google FCM (TCP 5228 + mtalk hosts).
        /// Default <c>false</c> — do not break Chrome push for normal users.
        /// Enable after confirmed MitM / Chrome sync token theft (see CHANGELOG 0.8.6 June 13–14 chain).
        /// </summary>
        public bool BlockFcmPushChannel { get; set; } = false;

        /// <summary>
        /// v1.8.3: When false (default), IPSec only blocks attack/legacy ports nobody needs
        /// (Telnet, rsh, TFTP, Meterpreter/BackOrifice-class ports). SSH, RDP, SMB, VNC,
        /// databases, SOCKS, Docker stay open. When true, also block that broader service set
        /// (locked-down host / kiosk mode).
        /// </summary>
        public bool RestrictivePortHardening { get; set; } = false;

        /// <summary>
        /// v1.6.3: Trusted USB devices as VID:PID (hex, e.g. "0951:1666" for Kingston DataTraveler).
        /// New mass-storage/composite devices matching these IDs are baselined at low severity
        /// and never auto-disabled. HID BadUSB rules still apply to unknown keyboards.
        /// </summary>
        public string[] TrustedUsbDevices { get; set; } = Array.Empty<string>();

        /// <summary>
        /// v1.6.3: When true (default), auto-disable USB nodes that fail descriptor requests
        /// (VID_0000 / "Device Descriptor Request Failed") via registry ConfigFlags.
        /// </summary>
        public bool AutoDisableFailedUsbEnumeration { get; set; } = true;

        public CveShieldConfig CveShield { get; set; } = new();
    }

    public class ThreatReportingConfig
    {
        public bool Enabled { get; set; } = true;
        public string? AbuseIpDbApiKey { get; set; }
        public string? UrlhausAuthToken { get; set; }
        public string? MalwareBazaarApiKey { get; set; }
        public bool ReportToMalwareBazaar { get; set; } = true;
        public bool ReportToUrlhaus { get; set; } = true;

        /// <summary>
        /// URL of the Cloudflare Worker proxy that holds API keys server-side.
        /// When set, reports go to this endpoint instead of directly to abuse.ch.
        /// This allows open-source distribution without leaking API keys.
        /// </summary>
        public string? ProxyEndpoint { get; set; }

        /// <summary>
        /// v1.6.0: Shared secret matching Worker env SENTINEL_SHARED_SECRET.
        /// Used as the HMAC-SHA256 key for all proxy requests. Required (≥16 chars)
        /// when Enabled+ProxyEndpoint are set; reporting fails closed without it.
        /// Never commit production secrets to source control.
        /// </summary>
        public string? ProxySharedSecret { get; set; }
    }

    /// <summary>
    /// v1.7.7+ — Automatic local evidence packs + optional TI indicator share
    /// for high-confidence hacking / attack detections.
    /// Does not file police reports (no public LE API); prepares packs and portal links.
    /// v1.7.8: reportable-grade policy, integrity manifest/HMAC, victim affidavit.
    /// </summary>
    public class AutoIncidentReportingConfig
    {
        /// <summary>Master switch. Default on.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>Write police-ready packs under ProgramData\Sentinel\IncidentReports.</summary>
        public bool GenerateLocalEvidencePack { get; set; } = true;

        /// <summary>
        /// Submit hashes/URLs/IPs via ThreatReportService (MalwareBazaar/URLhaus/AbuseIPDB).
        /// Requires ThreatReporting proxy secret. Community intel — not law enforcement.
        /// </summary>
        public bool ReportThreatIntel { get; set; } = true;

        /// <summary>Show a critical toast when a pack is written.</summary>
        public bool NotifyUser { get; set; } = true;

        /// <summary>
        /// v1.7.8: When true (default), only reportable-grade events produce packs:
        /// kill-authorized at high confidence, NetworkIsolate for C2-class signals,
        /// or Tier1 attack signals at MinConfidence — no low-signal noise.
        /// </summary>
        public bool ReportableGradeOnly { get; set; } = true;

        /// <summary>Minimum confidence for reportable-grade Tier1 / isolate paths (default 0.85).</summary>
        public double MinConfidence { get; set; } = 0.85;

        /// <summary>
        /// Floor confidence for kill-authorized packs when ReportableGradeOnly is true (default 0.80).
        /// When ReportableGradeOnly is false, uses min(MinConfidence, 0.70) for broader capture.
        /// </summary>
        public double KillAuthorizedMinConfidence { get; set; } = 0.80;

        /// <summary>Report kill-authorized detections (above KillAuthorizedMinConfidence).</summary>
        public bool IncludeKillAuthorized { get; set; } = true;

        /// <summary>Include NetworkIsolate when signal looks like C2 / attack (not every isolate).</summary>
        public bool IncludeNetworkIsolate { get; set; } = true;

        /// <summary>
        /// v1.7.8: Write MANIFEST.sha256, evidence_manifest.json, MANIFEST.hmac, chain_of_custody.txt.
        /// </summary>
        public bool IncludeIntegrityManifest { get; set; } = true;

        /// <summary>v1.7.8: Write victim_affidavit.txt fill-in template for the complainant.</summary>
        public bool IncludeVictimAffidavit { get; set; } = true;

        /// <summary>v1.7.8: Also create a .zip of the pack after integrity sealing.</summary>
        public bool CreateZipExport { get; set; } = true;

        /// <summary>Optional pre-fill for affidavit (user may complete remaining fields by hand).</summary>
        public string? VictimFullName { get; set; }
        public string? VictimEmail { get; set; }
        public string? VictimPhone { get; set; }
        public string? VictimAddress { get; set; }

        /// <summary>
        /// ISO 3166-1 alpha-2 override for filing portal (e.g. "HR", "US").
        /// Null = detect from Windows region.
        /// </summary>
        public string? CountryCode { get; set; }

        /// <summary>Override pack output directory. Null = ProgramData\Sentinel\IncidentReports.</summary>
        public string? ReportDirectory { get; set; }

        /// <summary>Per rule+pid cooldown in seconds (default 5 minutes).</summary>
        public int CooldownSeconds { get; set; } = 300;

        /// <summary>Hard cap on packs written per rolling hour (default 20).</summary>
        public int MaxPacksPerHour { get; set; } = 20;
    }

    public class TelemetryEvent
    {
        public string Type { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
    }

    public class ProcessTelemetry : TelemetryEvent
    {
        public string ImagePath { get; set; } = string.Empty;
        public int ParentProcessId { get; set; }
        public string ParentProcessName { get; set; } = string.Empty;
        public string CommandLine { get; set; } = string.Empty;
    }

    public class NetworkTelemetry : TelemetryEvent
    {
        public string LocalAddress { get; set; } = string.Empty;
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; } = string.Empty;
        public int RemotePort { get; set; }
        public string Protocol { get; set; } = "TCP";
        public string State { get; set; } = "ESTABLISHED";
    }

    public class FileActivityTelemetry : TelemetryEvent
    {
        public string FilePath { get; set; } = string.Empty;
        public string OperationType { get; set; } = string.Empty; // WRITE, RENAME, DELETE, etc.
        public string? TargetPath { get; set; }
    }

    public class ThreatIntelTelemetry : TelemetryEvent
    {
        public int TargetProcessId { get; set; }
        public string ApiName { get; set; } = string.Empty; // VirtualAllocEx, SetThreadContext, etc.
        public string Protection { get; set; } = string.Empty;
    }

    public class DetectionEvent
    {
        public string RuleName { get; set; } = string.Empty;
        public string Evidence { get; set; } = string.Empty;
        public string Reasoning { get; set; } = string.Empty;
        public double Confidence { get; set; }
        public DetectionTier Tier { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public int ProcessId { get; set; }
        public SignalType SignalType { get; set; } = SignalType.Generic;
        public Dictionary<string, string> Metadata { get; set; } = new();
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public ResponseAction AuthorizedResponse { get; set; } = ResponseAction.LogOnly;
        public bool KillAuthorized => AuthorizedResponse >= ResponseAction.KillProcess;
    }

    public class ResponseEvent
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string ActionTaken { get; set; } = string.Empty;
        public string Reason { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public double ExecutionTimeMs { get; set; }
    }
}
