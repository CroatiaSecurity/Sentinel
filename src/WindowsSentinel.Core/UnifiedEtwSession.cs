using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Unified ETW real-time session that subscribes to multiple system providers simultaneously.
    /// 
    /// This replaces the poll-based architecture for process, file, registry, DNS, network,
    /// firewall, and task scheduler monitoring. Instead of each monitor independently polling
    /// every 5-30 seconds, all telemetry arrives event-driven at ~50ms latency through a
    /// single kernel trace session.
    /// 
    /// PROVIDERS SUBSCRIBED:
    ///   1. Microsoft-Windows-Kernel-Process     — Process start/stop (PID, PPID, image, cmdline)
    ///   2. Microsoft-Windows-Kernel-File        — File create/write/delete/rename (all volumes)
    ///   3. Microsoft-Windows-Kernel-Registry    — Registry key/value create/modify/delete
    ///   4. Microsoft-Windows-DNS-Client         — All DNS resolution queries and responses
    ///   5. Microsoft-Windows-Threat-Intelligence — Kernel-level injection APIs (VirtualAllocEx, etc.)
    ///   6. Microsoft-Windows-PowerShell         — Script block logging (Event ID 4104)
    ///   7. Microsoft-Windows-Windows Firewall With Advanced Security — Rule changes
    ///   8. Microsoft-Windows-TaskScheduler      — Task creation/modification/deletion
    ///   9. Microsoft-Windows-Kernel-Network     — TCP/UDP connection state transitions
    /// 
    /// ARCHITECTURE:
    ///   UnifiedEtwSession owns the trace session lifecycle (Start/Stop).
    ///   Events are dispatched to registered IEtwEventHandler callbacks by provider GUID.
    ///   Handlers convert raw events into typed telemetry and feed TelemetryFusionEngine.
    /// 
    /// REQUIREMENTS: Administrator/SYSTEM privileges for kernel providers.
    /// FALLBACK: If session start fails, sets IsActive=false and logs warning.
    ///           Monitors should check IsActive and fall back to polling if false.
    /// 
    /// THREAD MODEL: ProcessTrace blocks on a dedicated thread. Callbacks execute on
    ///   the ETW thread pool. Handlers must be non-blocking (queue work if needed).
    /// </summary>
    public sealed class UnifiedEtwSession : IDisposable
    {
        private readonly ILogger<UnifiedEtwSession> _logger;
        private readonly Dictionary<Guid, List<Action<EtwRawEvent>>> _handlers = new();
        private readonly object _handlersLock = new();

        private Thread? _processingThread;
        private long _traceHandle;
        private long _sessionHandle;
        private volatile bool _stopping;
        private long _eventsProcessed;
        private long _eventsDropped;

        /// <summary>True if the ETW session started successfully and is actively consuming events.</summary>
        public bool IsActive { get; private set; }

        /// <summary>Total events processed since session start.</summary>
        public long EventsProcessed => Interlocked.Read(ref _eventsProcessed);

        /// <summary>Events dropped due to handler errors.</summary>
        public long EventsDropped => Interlocked.Read(ref _eventsDropped);

        // Session name — unique to prevent collision with other ETW consumers
        private const string SessionName = "SentinelUnifiedTrace";

        // ═══════════════════════════════════════════════════════════════
        // ETW Provider GUIDs
        // ═══════════════════════════════════════════════════════════════

        public static class Providers
        {
            /// <summary>Process start/stop events (Event IDs 1, 2)</summary>
            public static readonly Guid KernelProcess = new("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");

            /// <summary>File I/O events — create, write, delete, rename, close</summary>
            public static readonly Guid KernelFile = new("EDD08927-9CC4-4E65-B970-C2560FB5C289");

            /// <summary>Registry key/value manipulation events</summary>
            public static readonly Guid KernelRegistry = new("70EB4F03-C1DE-4F73-A051-33D13D5413BD");

            /// <summary>DNS query and response events</summary>
            public static readonly Guid DnsClient = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");

            /// <summary>Kernel-level API observation (injection, memory manipulation)</summary>
            public static readonly Guid ThreatIntelligence = new("F4E1897C-BB5D-5668-F1D8-040F4D8DD344");

            /// <summary>PowerShell script block logging (Event ID 4104)</summary>
            public static readonly Guid PowerShell = new("A0C1853B-5C40-4B15-8766-3CF1C58F985A");

            /// <summary>Windows Firewall rule changes</summary>
            public static readonly Guid Firewall = new("D1BC9AFF-2ABF-4D71-9146-ECB2A986EB85");

            /// <summary>Task Scheduler task lifecycle events</summary>
            public static readonly Guid TaskScheduler = new("DE7B24EA-73C8-4A09-985D-5BDADCFA9017");

            /// <summary>TCP/IP connection events (connect, disconnect, retransmit)</summary>
            public static readonly Guid KernelNetwork = new("7DD42A49-5329-4832-8DFD-43D979153A88");
        }

        // Provider configurations: GUID → (Level, MatchAnyKeyword)
        private static readonly (Guid Guid, byte Level, ulong Keywords)[] ProviderConfigs = new[]
        {
            (Providers.KernelProcess,       TRACE_LEVEL_INFORMATION, 0x10UL),   // WINEVENT_KEYWORD_PROCESS
            (Providers.KernelFile,          TRACE_LEVEL_INFORMATION, 0x1000UL), // NameCreate + NameDelete + Create
            (Providers.KernelRegistry,      TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFFUL),
            (Providers.DnsClient,           TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFFUL),
            (Providers.ThreatIntelligence,  TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFFUL),
            (Providers.PowerShell,          TRACE_LEVEL_VERBOSE,     0xFFFFFFFFFFFFFFFFUL),
            (Providers.Firewall,            TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFFUL),
            (Providers.TaskScheduler,       TRACE_LEVEL_INFORMATION, 0xFFFFFFFFFFFFFFFFUL),
            (Providers.KernelNetwork,       TRACE_LEVEL_INFORMATION, 0x50UL),   // TcpIp send/recv + connect/disconnect
        };

        public UnifiedEtwSession(ILogger<UnifiedEtwSession> logger)
        {
            _logger = logger;
        }

        // ═══════════════════════════════════════════════════════════════
        // Handler Registration
        // ═══════════════════════════════════════════════════════════════

        /// <summary>
        /// Registers a callback for events from a specific provider.
        /// Must be called BEFORE StartAsync. Multiple handlers per provider are supported.
        /// </summary>
        public void RegisterHandler(Guid providerGuid, Action<EtwRawEvent> handler)
        {
            lock (_handlersLock)
            {
                if (!_handlers.TryGetValue(providerGuid, out var list))
                {
                    list = new List<Action<EtwRawEvent>>();
                    _handlers[providerGuid] = list;
                }
                list.Add(handler);
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // Session Lifecycle
        // ═══════════════════════════════════════════════════════════════

        /// <summary>
        /// Starts the unified ETW session and enables all configured providers.
        /// If the session cannot be started (e.g., insufficient privileges), sets IsActive=false.
        /// </summary>
        public Task StartAsync(CancellationToken ct)
        {
            try
            {
                // Clean up any stale session from a previous crash
                StopExistingSession();

                if (!CreateSession())
                {
                    IsActive = false;
                    _logger.LogWarning(
                        "[UnifiedEtwSession] Failed to create trace session. " +
                        "Monitors will fall back to polling. Ensure the service runs as SYSTEM/Admin.");
                    return Task.CompletedTask;
                }

                // Enable each provider on the session
                int enabledCount = 0;
                foreach (var (guid, level, keywords) in ProviderConfigs)
                {
                    if (EnableProvider(guid, level, keywords))
                    {
                        enabledCount++;
                    }
                    else
                    {
                        _logger.LogDebug("[UnifiedEtwSession] Failed to enable provider {Guid}", guid);
                    }
                }

                if (enabledCount == 0)
                {
                    IsActive = false;
                    _logger.LogWarning("[UnifiedEtwSession] No providers could be enabled. Session inactive.");
                    StopSession();
                    return Task.CompletedTask;
                }

                // Start the processing thread
                IsActive = true;
                _processingThread = new Thread(ProcessTraceThread)
                {
                    Name = "Sentinel-UnifiedETW",
                    IsBackground = true,
                    Priority = ThreadPriority.AboveNormal // Ensure we don't miss events under load
                };
                _processingThread.Start();

                _logger.LogInformation(
                    "[UnifiedEtwSession] Started with {Count}/{Total} providers enabled. " +
                    "Event-driven telemetry active (~50ms latency).",
                    enabledCount, ProviderConfigs.Length);
            }
            catch (Exception ex)
            {
                IsActive = false;
                _logger.LogWarning(ex, "[UnifiedEtwSession] Startup exception. Monitors will fall back to polling.");
            }

            return Task.CompletedTask;
        }

        /// <summary>Stops the ETW session and processing thread.</summary>
        public Task StopAsync()
        {
            _stopping = true;
            StopSession();
            _processingThread?.Join(5000);

            _logger.LogInformation(
                "[UnifiedEtwSession] Stopped. Processed: {Processed}, Dropped: {Dropped}",
                EventsProcessed, EventsDropped);

            IsActive = false;
            return Task.CompletedTask;
        }

        public void Dispose()
        {
            if (!_stopping) StopAsync().GetAwaiter().GetResult();
        }

        // ═══════════════════════════════════════════════════════════════
        // ETW Session Management
        // ═══════════════════════════════════════════════════════════════

        private bool CreateSession()
        {
            int propsSize = Marshal.SizeOf<EVENT_TRACE_PROPERTIES>();
            int sessionNameSize = (SessionName.Length + 1) * 2;
            int bufferSize = propsSize + sessionNameSize;
            IntPtr propsPtr = Marshal.AllocHGlobal(bufferSize);

            try
            {
                // Zero the buffer
                for (int i = 0; i < bufferSize; i++)
                    Marshal.WriteByte(propsPtr, i, 0);

                var props = new EVENT_TRACE_PROPERTIES();
                props.Wnode.BufferSize = (uint)bufferSize;
                props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
                props.Wnode.ClientContext = 1; // QPC clock resolution (highest precision)
                props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
                props.LoggerNameOffset = (uint)propsSize;
                // Buffer configuration for high-throughput
                props.MinimumBuffers = 16;
                props.MaximumBuffers = 64;
                props.BufferSize2 = 256; // 256 KB per buffer

                Marshal.StructureToPtr(props, propsPtr, false);

                // Write session name
                var nameBytes = Encoding.Unicode.GetBytes(SessionName + "\0");
                Marshal.Copy(nameBytes, 0, propsPtr + propsSize, nameBytes.Length);

                long sessionHandle = 0;
                uint status = StartTraceW(out sessionHandle, SessionName, propsPtr);

                if (status != 0)
                {
                    _logger.LogDebug("[UnifiedEtwSession] StartTrace failed: status={Status}", status);
                    return false;
                }

                _sessionHandle = sessionHandle;
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(propsPtr);
            }
        }

        private bool EnableProvider(Guid providerGuid, byte level, ulong keywords)
        {
            var enableParams = new ENABLE_TRACE_PARAMETERS
            {
                Version = 2,
                EnableProperty = 0
            };

            var guid = providerGuid; // Local copy for ref
            uint status = EnableTraceEx2(
                _sessionHandle,
                ref guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                level,
                keywords,
                0,
                0,
                ref enableParams);

            return status == 0;
        }

        private void StopExistingSession()
        {
            try
            {
                int propsSize = Marshal.SizeOf<EVENT_TRACE_PROPERTIES>();
                int bufferSize = propsSize + (SessionName.Length + 1) * 2;
                IntPtr propsPtr = Marshal.AllocHGlobal(bufferSize);
                try
                {
                    for (int i = 0; i < bufferSize; i++)
                        Marshal.WriteByte(propsPtr, i, 0);
                    Marshal.WriteInt32(propsPtr, 0, bufferSize);
                    Marshal.WriteInt32(propsPtr, Marshal.OffsetOf<EVENT_TRACE_PROPERTIES>(nameof(EVENT_TRACE_PROPERTIES.LoggerNameOffset)).ToInt32(), propsSize);
                    ControlTraceW(0, SessionName, propsPtr, EVENT_TRACE_CONTROL_STOP);
                }
                finally { Marshal.FreeHGlobal(propsPtr); }
            }
            catch { }
        }

        private void StopSession()
        {
            try
            {
                if (_traceHandle != 0 && _traceHandle != INVALID_PROCESSTRACE_HANDLE)
                {
                    CloseTrace(_traceHandle);
                    _traceHandle = 0;
                }

                if (_sessionHandle != 0)
                {
                    int propsSize = Marshal.SizeOf<EVENT_TRACE_PROPERTIES>();
                    int bufferSize = propsSize + (SessionName.Length + 1) * 2;
                    IntPtr propsPtr = Marshal.AllocHGlobal(bufferSize);
                    try
                    {
                        for (int i = 0; i < bufferSize; i++)
                            Marshal.WriteByte(propsPtr, i, 0);
                        Marshal.WriteInt32(propsPtr, 0, bufferSize);
                        Marshal.WriteInt32(propsPtr, Marshal.OffsetOf<EVENT_TRACE_PROPERTIES>(nameof(EVENT_TRACE_PROPERTIES.LoggerNameOffset)).ToInt32(), propsSize);
                        ControlTraceW(_sessionHandle, null, propsPtr, EVENT_TRACE_CONTROL_STOP);
                    }
                    finally { Marshal.FreeHGlobal(propsPtr); }
                    _sessionHandle = 0;
                }
            }
            catch { }
        }

        // ═══════════════════════════════════════════════════════════════
        // Event Processing
        // ═══════════════════════════════════════════════════════════════

        private void ProcessTraceThread()
        {
            try
            {
                var logFile = new EVENT_TRACE_LOGFILEW
                {
                    LoggerName = SessionName,
                    LogFileMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
                    EventRecordCallback = OnEventRecord
                };

                _traceHandle = OpenTraceW(ref logFile);
                if (_traceHandle == INVALID_PROCESSTRACE_HANDLE)
                {
                    _logger.LogWarning("[UnifiedEtwSession] OpenTrace failed.");
                    IsActive = false;
                    return;
                }

                // ProcessTrace blocks until session is stopped
                var handles = new long[] { _traceHandle };
                ProcessTrace(handles, 1, IntPtr.Zero, IntPtr.Zero);
            }
            catch (Exception ex)
            {
                if (!_stopping)
                    _logger.LogError(ex, "[UnifiedEtwSession] ProcessTrace thread exception");
            }
        }

        private void OnEventRecord(ref EVENT_RECORD eventRecord)
        {
            if (_stopping) return;

            Interlocked.Increment(ref _eventsProcessed);

            var providerGuid = eventRecord.EventHeader.ProviderId;

            List<Action<EtwRawEvent>>? handlerList;
            lock (_handlersLock)
            {
                if (!_handlers.TryGetValue(providerGuid, out handlerList))
                    return; // No handlers for this provider
            }

            // Build the raw event struct for handlers
            var rawEvent = new EtwRawEvent
            {
                ProviderId = providerGuid,
                EventId = eventRecord.EventHeader.EventDescriptor.Id,
                Version = eventRecord.EventHeader.EventDescriptor.Version,
                Level = eventRecord.EventHeader.EventDescriptor.Level,
                Opcode = eventRecord.EventHeader.EventDescriptor.Opcode,
                Keyword = eventRecord.EventHeader.EventDescriptor.Keyword,
                ProcessId = (int)eventRecord.EventHeader.ProcessId,
                ThreadId = (int)eventRecord.EventHeader.ThreadId,
                Timestamp = DateTime.FromFileTimeUtc(eventRecord.EventHeader.TimeStamp),
                UserData = eventRecord.UserData,
                UserDataLength = eventRecord.UserDataLength
            };

            foreach (var handler in handlerList)
            {
                try
                {
                    handler(rawEvent);
                }
                catch
                {
                    Interlocked.Increment(ref _eventsDropped);
                }
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // P/Invoke Declarations
        // ═══════════════════════════════════════════════════════════════

        private const uint WNODE_FLAG_TRACED_GUID = 0x00020000;
        private const uint EVENT_TRACE_REAL_TIME_MODE = 0x00000100;
        private const uint EVENT_TRACE_CONTROL_STOP = 1;
        private const uint EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1;
        private const byte TRACE_LEVEL_INFORMATION = 4;
        private const byte TRACE_LEVEL_VERBOSE = 5;
        private const uint PROCESS_TRACE_MODE_REAL_TIME = 0x00000100;
        private const uint PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000;
        private const long INVALID_PROCESSTRACE_HANDLE = -1;

        [StructLayout(LayoutKind.Sequential)]
        private struct WNODE_HEADER
        {
            public uint BufferSize;
            public uint ProviderId;
            public ulong HistoricalContext;
            public long TimeStamp;
            public Guid Guid;
            public uint ClientContext;
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EVENT_TRACE_PROPERTIES
        {
            public WNODE_HEADER Wnode;
            public uint BufferSize2;
            public uint MinimumBuffers;
            public uint MaximumBuffers;
            public uint MaximumFileSize;
            public uint LogFileMode;
            public uint FlushTimer;
            public uint EnableFlags;
            public int AgeLimit;
            public uint NumberOfBuffers;
            public uint FreeBuffers;
            public uint EventsLost;
            public uint BuffersWritten;
            public uint LogBuffersLost;
            public uint RealTimeBuffersLost;
            public IntPtr LoggerThreadId;
            public uint LogFileNameOffset;
            public uint LoggerNameOffset;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ENABLE_TRACE_PARAMETERS
        {
            public uint Version;
            public uint EnableProperty;
            public uint ControlFlags;
            public Guid SourceId;
            public IntPtr EnableFilterDesc;
            public uint FilterDescCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EVENT_DESCRIPTOR
        {
            public ushort Id;
            public byte Version;
            public byte Channel;
            public byte Level;
            public byte Opcode;
            public ushort Task;
            public ulong Keyword;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EVENT_HEADER
        {
            public ushort Size;
            public ushort HeaderType;
            public ushort Flags;
            public ushort EventProperty;
            public uint ThreadId;
            public uint ProcessId;
            public long TimeStamp;
            public Guid ProviderId;
            public EVENT_DESCRIPTOR EventDescriptor;
            public long ProcessorTime;
            public Guid ActivityId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EVENT_RECORD
        {
            public EVENT_HEADER EventHeader;
            public uint BufferContext;
            public ushort ExtendedDataCount;
            public ushort UserDataLength;
            public IntPtr ExtendedData;
            public IntPtr UserData;
            public IntPtr UserContext;
        }

        private delegate void EventRecordCallbackDelegate(ref EVENT_RECORD eventRecord);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct EVENT_TRACE_LOGFILEW
        {
            [MarshalAs(UnmanagedType.LPWStr)] public string LogFileName;
            [MarshalAs(UnmanagedType.LPWStr)] public string LoggerName;
            public long CurrentTime;
            public uint BuffersRead;
            public uint LogFileMode;
            public EVENT_RECORD CurrentEvent;
            public uint LogfileHeader;
            public IntPtr BufferCallback;
            public uint BufferSize;
            public uint Filled;
            public uint EventsLost;
            [MarshalAs(UnmanagedType.FunctionPtr)] public EventRecordCallbackDelegate EventRecordCallback;
            public uint IsKernelTrace;
            public IntPtr Context;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint StartTraceW(out long sessionHandle, string sessionName, IntPtr properties);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint ControlTraceW(long sessionHandle, string? sessionName, IntPtr properties, uint controlCode);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint EnableTraceEx2(long traceHandle, ref Guid providerId, uint controlCode,
            byte level, ulong matchAnyKeyword, ulong matchAllKeyword, uint timeout, ref ENABLE_TRACE_PARAMETERS enableParameters);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern long OpenTraceW(ref EVENT_TRACE_LOGFILEW logFile);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint ProcessTrace(long[] handleArray, uint handleCount, IntPtr startTime, IntPtr endTime);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint CloseTrace(long traceHandle);
    }

    // ═══════════════════════════════════════════════════════════════
    // Raw Event Structure (passed to handlers)
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// Lightweight struct representing a raw ETW event delivered to registered handlers.
    /// Contains the provider, event ID, and a pointer to the user data payload.
    /// Handlers must copy any data they need before returning (pointer lifetime = callback scope).
    /// </summary>
    public struct EtwRawEvent
    {
        /// <summary>Which provider emitted this event.</summary>
        public Guid ProviderId;
        /// <summary>Event ID within the provider's manifest.</summary>
        public ushort EventId;
        /// <summary>Event schema version.</summary>
        public byte Version;
        /// <summary>Event severity level.</summary>
        public byte Level;
        /// <summary>Event opcode (start/stop/info).</summary>
        public byte Opcode;
        /// <summary>Event keyword flags.</summary>
        public ulong Keyword;
        /// <summary>PID that generated the event (from ETW header).</summary>
        public int ProcessId;
        /// <summary>Thread that generated the event.</summary>
        public int ThreadId;
        /// <summary>High-precision timestamp from ETW.</summary>
        public DateTime Timestamp;
        /// <summary>Pointer to event-specific payload data. Valid only during callback.</summary>
        public IntPtr UserData;
        /// <summary>Length of UserData in bytes.</summary>
        public ushort UserDataLength;
    }
}
