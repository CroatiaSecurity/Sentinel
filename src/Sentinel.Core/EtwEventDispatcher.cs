using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Converts raw ETW events from UnifiedEtwSession into typed telemetry objects
    /// and feeds them into the TelemetryFusionEngine → DetectionEngine pipeline.
    /// 
    /// Each provider has a dedicated handler method registered with UnifiedEtwSession.
    /// Handlers parse the provider-specific event payload and emit the appropriate
    /// telemetry type (ProcessTelemetry, FileActivityTelemetry, NetworkTelemetry, etc.).
    /// 
    /// DESIGN RULES:
    ///   - Handlers must be non-blocking (ETW callback thread pool is limited)
    ///   - Parse defensively (payload layouts vary by Windows build)
    ///   - Never throw from a handler (exceptions are swallowed by the session)
    ///   - Copy any data from UserData pointer before returning
    /// </summary>
    public sealed class EtwEventDispatcher
    {
        private readonly TelemetryFusionEngine _fusionEngine;
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly BehavioralBaselineService? _baseline;
        private readonly ILogger<EtwEventDispatcher> _logger;

        // Event IDs for Microsoft-Windows-Kernel-Process
        private const ushort ProcessStart = 1;
        private const ushort ProcessStop = 2;

        // Event IDs for Microsoft-Windows-Kernel-File
        private const ushort FileCreate = 12;
        private const ushort FileDelete = 26;
        private const ushort FileRename = 15;  // SetInformation with rename class
        private const ushort FileWrite = 16;   // Write operations
        private const ushort FileNameCreate = 10;
        private const ushort FileNameDelete = 11;

        // Event IDs for Microsoft-Windows-Kernel-Registry
        private const ushort RegCreateKey = 1;
        private const ushort RegOpenKey = 2;
        private const ushort RegDeleteKey = 3;
        private const ushort RegSetValue = 5;
        private const ushort RegDeleteValue = 6;

        // Event IDs for Microsoft-Windows-DNS-Client
        private const ushort DnsQueryStart = 1001;  // QueryStart
        private const ushort DnsQueryComplete = 1002;

        // Event IDs for Microsoft-Windows-PowerShell
        private const ushort ScriptBlockLogging = 4104;

        // Event IDs for Microsoft-Windows-TaskScheduler
        private const ushort TaskCreated = 106;
        private const ushort TaskUpdated = 140;
        private const ushort TaskDeleted = 141;

        // Event IDs for Firewall
        private const ushort FirewallRuleAdded = 2004;
        private const ushort FirewallRuleModified = 2005;
        private const ushort FirewallRuleDeleted = 2006;

        // Event IDs for Kernel-Network (TCP/IP)
        private const ushort TcpConnect = 12; // TcpIp/Connect
        private const ushort TcpDisconnect = 14;
        private const ushort TcpAccept = 15;

        public EtwEventDispatcher(
            TelemetryFusionEngine fusionEngine,
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache,
            ILogger<EtwEventDispatcher> logger,
            BehavioralBaselineService? baseline = null)
        {
            _fusionEngine = fusionEngine;
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _baseline = baseline;
            _logger = logger;
        }

        /// <summary>
        /// Registers all provider handlers with the unified ETW session.
        /// Call this before UnifiedEtwSession.StartAsync().
        /// </summary>
        public void RegisterHandlers(UnifiedEtwSession session)
        {
            session.RegisterHandler(UnifiedEtwSession.Providers.KernelProcess, OnKernelProcessEvent);
            session.RegisterHandler(UnifiedEtwSession.Providers.KernelFile, OnKernelFileEvent);
            session.RegisterHandler(UnifiedEtwSession.Providers.KernelRegistry, OnKernelRegistryEvent);
            session.RegisterHandler(UnifiedEtwSession.Providers.DnsClient, OnDnsClientEvent);
            session.RegisterHandler(UnifiedEtwSession.Providers.ThreatIntelligence, OnThreatIntelEvent);
            session.RegisterHandler(UnifiedEtwSession.Providers.PowerShell, OnPowerShellEvent);
            session.RegisterHandler(UnifiedEtwSession.Providers.Firewall, OnFirewallEvent);
            session.RegisterHandler(UnifiedEtwSession.Providers.TaskScheduler, OnTaskSchedulerEvent);
            session.RegisterHandler(UnifiedEtwSession.Providers.KernelNetwork, OnKernelNetworkEvent);
        }

        // ═══════════════════════════════════════════════════════════════
        // Process Events (Microsoft-Windows-Kernel-Process)
        // ═══════════════════════════════════════════════════════════════

        private void OnKernelProcessEvent(EtwRawEvent evt)
        {
            if (evt.EventId == ProcessStart)
            {
                HandleProcessStart(evt);
            }
            // ProcessStop can be used for ancestry cache cleanup
        }

        private void HandleProcessStart(EtwRawEvent evt)
        {
            if (evt.UserData == IntPtr.Zero || evt.UserDataLength < 24) return;

            int pid = Marshal.ReadInt32(evt.UserData, 0);
            int parentPid = Marshal.ReadInt32(evt.UserData, 12);

            if (pid <= 4) return;

            // Resolve process details via PID (more reliable than variable-length ETW payload)
            string imagePath = SecurityValidation.GetProcessImagePath(pid) ?? "";
            string processName = !string.IsNullOrEmpty(imagePath) ? Path.GetFileName(imagePath) : "";

            if (string.IsNullOrEmpty(processName))
            {
                try { processName = Process.GetProcessById(pid).ProcessName; } catch { return; }
            }

            // Resolve parent
            string parentName = "";
            try { parentName = _ancestryCache.GetProcessInfo(parentPid).name; } catch { }

            // Update baseline
            _baseline?.RecordProcess(processName, imagePath, pid, parentName);

            // Emit telemetry
            var telemetry = new ProcessTelemetry
            {
                ProcessName = processName,
                ProcessId = pid,
                ParentProcessId = parentPid,
                ParentProcessName = parentName,
                ImagePath = imagePath,
                CommandLine = "", // Command line resolved by WMI fallback or ProcessAncestryCache
                Timestamp = evt.Timestamp
            };

            var context = _fusionEngine.FeedEvent(telemetry);
            _detectionEngine.SubmitTelemetry(context);
        }

        // ═══════════════════════════════════════════════════════════════
        // File Events (Microsoft-Windows-Kernel-File)
        // ═══════════════════════════════════════════════════════════════

        private void OnKernelFileEvent(EtwRawEvent evt)
        {
            // File events we care about: Create, Delete, Rename
            if (evt.EventId != FileNameCreate && evt.EventId != FileNameDelete &&
                evt.EventId != FileRename && evt.EventId != FileCreate &&
                evt.EventId != FileDelete)
                return;

            if (evt.UserData == IntPtr.Zero || evt.UserDataLength < 4) return;

            string operationType = evt.EventId switch
            {
                FileNameCreate or FileCreate => "CREATE",
                FileNameDelete or FileDelete => "DELETE",
                FileRename => "RENAME",
                FileWrite => "WRITE",
                _ => "UNKNOWN"
            };

            // Resolve the process that caused the file event
            int pid = evt.ProcessId;
            string processName = "";
            try
            {
                var info = _ancestryCache.GetProcessInfo(pid);
                processName = info.name;
            }
            catch
            {
                try { processName = Process.GetProcessById(pid).ProcessName; } catch { }
            }

            if (string.IsNullOrEmpty(processName)) return;

            // File path extraction from ETW payload is provider-specific.
            // Microsoft-Windows-Kernel-File uses opaque FileObject pointers in some events.
            // For high-value events (NameCreate/NameDelete), the filename is in UserData.
            string filePath = TryExtractFilePath(evt);
            if (string.IsNullOrEmpty(filePath)) return;

            var telemetry = new FileActivityTelemetry
            {
                ProcessName = processName,
                ProcessId = pid,
                FilePath = filePath,
                OperationType = operationType,
                Timestamp = evt.Timestamp
            };

            var context = _fusionEngine.FeedEvent(telemetry);
            _detectionEngine.SubmitTelemetry(context);
        }

        // ═══════════════════════════════════════════════════════════════
        // Registry Events (Microsoft-Windows-Kernel-Registry)
        // ═══════════════════════════════════════════════════════════════

        private void OnKernelRegistryEvent(EtwRawEvent evt)
        {
            if (evt.EventId != RegSetValue && evt.EventId != RegCreateKey &&
                evt.EventId != RegDeleteKey && evt.EventId != RegDeleteValue)
                return;

            // Registry events from the kernel provider.
            // Emit a detection directly for high-interest operations (Run keys, services)
            int pid = evt.ProcessId;
            string processName = "";
            try { processName = _ancestryCache.GetProcessInfo(pid).name; } catch { }
            if (string.IsNullOrEmpty(processName))
            {
                try { processName = Process.GetProcessById(pid).ProcessName; } catch { return; }
            }

            string opType = evt.EventId switch
            {
                RegSetValue => "SET_VALUE",
                RegCreateKey => "CREATE_KEY",
                RegDeleteKey => "DELETE_KEY",
                RegDeleteValue => "DELETE_VALUE",
                _ => "UNKNOWN"
            };

            // Key path extraction is complex (kernel registry events use key handles, not paths).
            // For now, log the event with metadata and let existing RegistryMonitor correlate.
            // This gives us the PID attribution that the current polling approach lacks.
            var telemetry = new RegistryTelemetry
            {
                ProcessName = processName,
                ProcessId = pid,
                OperationType = opType,
                Timestamp = evt.Timestamp
            };

            var context = _fusionEngine.FeedEvent(telemetry);
            _detectionEngine.SubmitTelemetry(context);
        }

        // ═══════════════════════════════════════════════════════════════
        // DNS Events (Microsoft-Windows-DNS-Client)
        // ═══════════════════════════════════════════════════════════════

        private void OnDnsClientEvent(EtwRawEvent evt)
        {
            // DNS query events give us domain name + PID
            if (evt.EventId != DnsQueryStart && evt.EventId != DnsQueryComplete) return;
            if (evt.UserData == IntPtr.Zero || evt.UserDataLength < 8) return;

            // DNS-Client provider payload for QueryStart:
            // QueryName (UnicodeString) at variable offset
            string queryName = TryExtractUnicodeString(evt.UserData, 0, evt.UserDataLength);
            if (string.IsNullOrEmpty(queryName)) return;

            int pid = evt.ProcessId;
            string processName = "";
            try { processName = _ancestryCache.GetProcessInfo(pid).name; } catch { }
            if (string.IsNullOrEmpty(processName))
            {
                try { processName = Process.GetProcessById(pid).ProcessName; } catch { }
            }

            var telemetry = new DnsTelemetry
            {
                ProcessName = processName,
                ProcessId = pid,
                QueryName = queryName,
                EventType = evt.EventId == DnsQueryStart ? "QUERY" : "RESPONSE",
                Timestamp = evt.Timestamp
            };

            var context = _fusionEngine.FeedEvent(telemetry);
            _detectionEngine.SubmitTelemetry(context);
        }

        // ═══════════════════════════════════════════════════════════════
        // Threat Intelligence Events
        // ═══════════════════════════════════════════════════════════════

        private void OnThreatIntelEvent(EtwRawEvent evt)
        {
            // Microsoft-Windows-Threat-Intelligence provides kernel-level API observation:
            // Remote allocation / thread context / section map APIs (names omitted for AV hygiene).
            // These events are the strongest injection signal available from userland.
            if (evt.UserData == IntPtr.Zero || evt.UserDataLength < 8) return;

            int callerPid = evt.ProcessId;
            // Target PID is typically in the event payload at offset 0 or 4
            int targetPid = evt.UserDataLength >= 8 ? Marshal.ReadInt32(evt.UserData, 0) : 0;

            string processName = "";
            try { processName = _ancestryCache.GetProcessInfo(callerPid).name; } catch { }
            if (string.IsNullOrEmpty(processName))
            {
                try { processName = Process.GetProcessById(callerPid).ProcessName; } catch { }
            }

            var telemetry = new ThreatIntelTelemetry
            {
                ProcessName = processName,
                ProcessId = callerPid,
                TargetProcessId = targetPid,
                ApiName = $"ThreatIntel_EventId_{evt.EventId}",
                Timestamp = evt.Timestamp
            };

            var context = _fusionEngine.FeedEvent(telemetry);
            _detectionEngine.SubmitTelemetry(context);
        }

        // ═══════════════════════════════════════════════════════════════
        // PowerShell Events (Script Block Logging)
        // ═══════════════════════════════════════════════════════════════

        private void OnPowerShellEvent(EtwRawEvent evt)
        {
            // Event ID 4104 = Script Block Logging (deobfuscated content)
            if (evt.EventId != ScriptBlockLogging) return;
            if (evt.UserData == IntPtr.Zero || evt.UserDataLength < 4) return;

            // Script block text is in the UserData as a Unicode string
            string scriptBlock = TryExtractUnicodeString(evt.UserData, 0, evt.UserDataLength);
            if (string.IsNullOrEmpty(scriptBlock)) return;

            int pid = evt.ProcessId;
            string processName = "powershell.exe";
            try { processName = Process.GetProcessById(pid).ProcessName; } catch { }

            // Feed as a ProcessTelemetry with the script block as the command line
            // This allows existing detection rules (ReverseShellRule, AttackToolsRule) to evaluate it
            var telemetry = new ProcessTelemetry
            {
                ProcessName = processName,
                ProcessId = pid,
                CommandLine = scriptBlock.Length > 8192 ? scriptBlock[..8192] : scriptBlock,
                ImagePath = "",
                ParentProcessName = "",
                Timestamp = evt.Timestamp
            };

            var context = _fusionEngine.FeedEvent(telemetry);
            _detectionEngine.SubmitTelemetry(context);
        }

        // ═══════════════════════════════════════════════════════════════
        // Firewall Events
        // ═══════════════════════════════════════════════════════════════

        private void OnFirewallEvent(EtwRawEvent evt)
        {
            if (evt.EventId != FirewallRuleAdded && evt.EventId != FirewallRuleModified &&
                evt.EventId != FirewallRuleDeleted)
                return;

            // Firewall rule changes — emit a detection signal for monitors to correlate
            string action = evt.EventId switch
            {
                FirewallRuleAdded => "RULE_ADDED",
                FirewallRuleModified => "RULE_MODIFIED",
                FirewallRuleDeleted => "RULE_DELETED",
                _ => "UNKNOWN"
            };

            _detectionEngine.SubmitTelemetry(new FusedTelemetryContext
            {
                TriggeringEvent = new FirewallTelemetry
                {
                    ProcessId = evt.ProcessId,
                    ProcessName = "",
                    Action = action,
                    Timestamp = evt.Timestamp
                }
            });
        }

        // ═══════════════════════════════════════════════════════════════
        // Task Scheduler Events
        // ═══════════════════════════════════════════════════════════════

        private void OnTaskSchedulerEvent(EtwRawEvent evt)
        {
            if (evt.EventId != TaskCreated && evt.EventId != TaskUpdated && evt.EventId != TaskDeleted)
                return;

            string action = evt.EventId switch
            {
                TaskCreated => "TASK_CREATED",
                TaskUpdated => "TASK_UPDATED",
                TaskDeleted => "TASK_DELETED",
                _ => "UNKNOWN"
            };

            _detectionEngine.SubmitTelemetry(new FusedTelemetryContext
            {
                TriggeringEvent = new TaskSchedulerTelemetry
                {
                    ProcessId = evt.ProcessId,
                    ProcessName = "",
                    Action = action,
                    Timestamp = evt.Timestamp
                }
            });
        }

        // ═══════════════════════════════════════════════════════════════
        // Network Events (Microsoft-Windows-Kernel-Network / TCPIP)
        // ═══════════════════════════════════════════════════════════════

        private void OnKernelNetworkEvent(EtwRawEvent evt)
        {
            // TCP connect/accept events give us PID + remote endpoint
            if (evt.EventId != TcpConnect && evt.EventId != TcpAccept) return;
            if (evt.UserData == IntPtr.Zero || evt.UserDataLength < 16) return;

            int pid = evt.ProcessId;
            string processName = "";
            try { processName = _ancestryCache.GetProcessInfo(pid).name; } catch { }
            if (string.IsNullOrEmpty(processName))
            {
                try { processName = Process.GetProcessById(pid).ProcessName; } catch { }
            }

            // TCP connection event payload layout varies; attempt basic IP extraction
            // Layout (simplified): localAddr(4) + localPort(2) + remoteAddr(4) + remotePort(2)
            // This is a best-effort parse — actual layout depends on Windows version
            if (evt.UserDataLength >= 16)
            {
                try
                {
                    // Skip to typical offset for remote address
                    byte b1 = Marshal.ReadByte(evt.UserData, 8);
                    byte b2 = Marshal.ReadByte(evt.UserData, 9);
                    byte b3 = Marshal.ReadByte(evt.UserData, 10);
                    byte b4 = Marshal.ReadByte(evt.UserData, 11);
                    string remoteAddr = $"{b1}.{b2}.{b3}.{b4}";

                    ushort remotePort = (ushort)Marshal.ReadInt16(evt.UserData, 12);
                    // Network byte order → host byte order
                    remotePort = (ushort)((remotePort >> 8) | (remotePort << 8));

                    if (remoteAddr == "0.0.0.0" || remoteAddr == "127.0.0.1") return;

                    var telemetry = new NetworkTelemetry
                    {
                        ProcessName = processName,
                        ProcessId = pid,
                        RemoteAddress = remoteAddr,
                        RemotePort = remotePort,
                        Protocol = "TCP",
                        State = evt.EventId == TcpConnect ? "CONNECT" : "ACCEPT",
                        Timestamp = evt.Timestamp
                    };

                    var context = _fusionEngine.FeedEvent(telemetry);
                    _detectionEngine.SubmitTelemetry(context);
                }
                catch { }
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // Helpers
        // ═══════════════════════════════════════════════════════════════

        private static string TryExtractFilePath(EtwRawEvent evt)
        {
            // Kernel-File NameCreate/NameDelete events include the filename in UserData
            // Layout: FileObject(8) + IRQL(1) + ... + FileName(UnicodeString)
            // Simplified: try to read a Unicode string starting after the first 8 bytes
            if (evt.UserDataLength < 16) return "";
            return TryExtractUnicodeString(evt.UserData, 8, evt.UserDataLength - 8);
        }

        private static string TryExtractUnicodeString(IntPtr data, int offset, int maxBytes)
        {
            try
            {
                if (data == IntPtr.Zero || maxBytes <= 0) return "";

                // Scan for a null-terminated Unicode string starting at offset
                int remaining = maxBytes - offset;
                if (remaining <= 0) return "";

                // Read up to 4096 chars max
                int maxChars = Math.Min(remaining / 2, 4096);
                var sb = new StringBuilder(maxChars);

                for (int i = 0; i < maxChars; i++)
                {
                    char c = (char)Marshal.ReadInt16(data, offset + i * 2);
                    if (c == '\0') break;
                    if (c < 32 && c != '\t') break; // Non-printable = corrupt
                    sb.Append(c);
                }

                return sb.Length > 0 ? sb.ToString() : "";
            }
            catch { return ""; }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // New Telemetry Types for ETW-sourced events
    // ═══════════════════════════════════════════════════════════════

    /// <summary>Registry operation telemetry from Kernel-Registry ETW provider.</summary>
    public class RegistryTelemetry : TelemetryEvent
    {
        public string OperationType { get; set; } = "";
        public string KeyPath { get; set; } = "";
        public string ValueName { get; set; } = "";
    }

    /// <summary>DNS query telemetry from DNS-Client ETW provider.</summary>
    public class DnsTelemetry : TelemetryEvent
    {
        public string QueryName { get; set; } = "";
        public string EventType { get; set; } = ""; // QUERY or RESPONSE
        public string ResponseData { get; set; } = "";
    }

    /// <summary>Firewall rule change telemetry.</summary>
    public class FirewallTelemetry : TelemetryEvent
    {
        public string Action { get; set; } = "";
        public string RuleName { get; set; } = "";
    }

    /// <summary>Task Scheduler operation telemetry.</summary>
    public class TaskSchedulerTelemetry : TelemetryEvent
    {
        public string Action { get; set; } = "";
        public string TaskName { get; set; } = "";
        public string TaskPath { get; set; } = "";
    }
}
