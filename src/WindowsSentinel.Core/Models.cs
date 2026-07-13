using System;
using System.Collections.Generic;

namespace WindowsSentinel.Core
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
        /// Empty = no Cast devices trusted = all Cast connections killed.
        /// Add your Chromecast/Nest IP here if you have one.
        /// </summary>
        public string[] TrustedCastDevices { get; set; } = Array.Empty<string>();

        // Dynamic polling intervals (configurable)
        public int DnsPollIntervalSeconds { get; set; } = 15;
        public int RouteTableScanIntervalSeconds { get; set; } = 15;
        public int RawDiskScanIntervalSeconds { get; set; } = 20;
        public int AntiTamperTimingTickMs { get; set; } = 2000;
        public int AntiTamperIntegrityTickMs { get; set; } = 10000;

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
        /// Shared secret key for verifying signature against Cloudflare Worker proxy.
        /// </summary>
        public string? ProxySharedSecret { get; set; }
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
