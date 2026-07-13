// PhysicalAccessMonitor — Detects unauthorized physical access at ALL times.
//
// Threat model: An attacker with physical access to the machine (e.g., a housemate)
// inserts USB devices, pairs Bluetooth peripherals, or initiates logon sessions while
// the owner is briefly away (toilet, kitchen, etc.). This monitor runs 24/7.
//
// What it detects:
//   1. New USB device insertions (BadUSB, data exfil, rubber ducky)
//   2. New Bluetooth HID device pairing (BadBT keyboard injection)
//   3. New interactive logon sessions (someone logging in)
//   4. Display wake after idle (someone waking the machine)
//   5. Console lock/unlock events (detect if machine was unlocked)
//
// Alerts are Tier1 with LogOnly response — they build an evidence trail.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace WindowsSentinel.Core
{
    public sealed class PhysicalAccessMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly MonitorRegistry _monitorRegistry;
        private readonly ILogger<PhysicalAccessMonitor> _logger;

        // Track state
        private readonly HashSet<string> _baselineUsbDevices = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _baselineBluetoothDevices = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<int> _baselineSessionIds = new();
        private uint _lastInputTick;
        private bool _wasIdle; // Was the user idle before current activity?
        private DateTime _idleStartTime = DateTime.MinValue;

        // Minimum seconds between repeated alerts of the same type
        private const int AlertCooldownSeconds = 60;
        private readonly Dictionary<string, DateTime> _categoryLastAlert = new();

        // Idle threshold: if no input for 2 minutes, user is "away"
        private const uint IdleThresholdMs = 120_000;

        [StructLayout(LayoutKind.Sequential)]
        private struct LASTINPUTINFO
        {
            public uint cbSize;
            public uint dwTime;
        }

        [DllImport("user32.dll")]
        private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

        [DllImport("kernel32.dll")]
        private static extern uint GetTickCount();

        public PhysicalAccessMonitor(
            DetectionEngine de,
            MonitorRegistry registry,
            ILogger<PhysicalAccessMonitor> l)
        {
            _detectionEngine = de;
            _monitorRegistry = registry;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[PhysicalAccessMonitor] Started — monitoring physical access 24/7");

            _monitorRegistry.Register("PhysicalAccessMonitor", MonitorCategory.UserProtection, this);

            // Baseline current state
            SnapshotUsbDevices(_baselineUsbDevices);
            SnapshotBluetoothDevices(_baselineBluetoothDevices);
            SnapshotSessionIds(_baselineSessionIds);

            var info = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
            GetLastInputInfo(ref info);
            _lastInputTick = info.dwTime;

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(5_000, ct); // Check every 5 seconds
                    _monitorRegistry.Heartbeat("PhysicalAccessMonitor");

                    // Track idle state
                    UpdateIdleState();

                    // Always monitor USB/BT/Session changes
                    await CheckNewUsbDevicesAsync();
                    await CheckNewBluetoothDevicesAsync();
                    await CheckNewSessionsAsync();

                    // Detect return-from-idle (someone woke the machine after user was away)
                    await CheckReturnFromIdleAsync();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[PhysicalAccessMonitor] Error in scan loop");
                }
            }
        }

        private bool CanAlert(string category)
        {
            if (_categoryLastAlert.TryGetValue(category, out var last))
            {
                if ((DateTime.UtcNow - last).TotalSeconds < AlertCooldownSeconds)
                    return false;
            }
            _categoryLastAlert[category] = DateTime.UtcNow;
            return true;
        }

        // ─── Idle State Tracking ────────────────────────────────────────────

        private void UpdateIdleState()
        {
            var info = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
            if (!GetLastInputInfo(ref info)) return;

            uint currentTick = GetTickCount();
            uint idleMs = currentTick - info.dwTime;

            if (idleMs >= IdleThresholdMs)
            {
                if (!_wasIdle)
                {
                    _wasIdle = true;
                    _idleStartTime = DateTime.Now;
                    _logger.LogDebug("[PhysicalAccessMonitor] User went idle at {Time}", _idleStartTime);
                }
            }

            _lastInputTick = info.dwTime;
        }

        // ─── Detection: Return from Idle ────────────────────────────────────

        private async Task CheckReturnFromIdleAsync()
        {
            var info = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
            if (!GetLastInputInfo(ref info)) return;

            uint currentTick = GetTickCount();
            uint idleMs = currentTick - info.dwTime;

            // User was idle but now there's fresh input
            if (_wasIdle && idleMs < 2000)
            {
                var awayDuration = DateTime.Now - _idleStartTime;
                _wasIdle = false;

                // Only alert if they were away at least 2 minutes
                if (awayDuration.TotalMinutes >= 2 && CanAlert("ReturnFromIdle"))
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Physical Access: Machine Resumed After Idle",
                        Evidence = $"Input activity resumed at {DateTime.Now:HH:mm:ss} after {awayDuration.TotalMinutes:F1} minutes idle. " +
                                   $"Machine was unattended since {_idleStartTime:HH:mm:ss}.",
                        Reasoning = "The machine was idle (no input) for over 2 minutes and someone began using it. " +
                                    "This creates a timestamp marker for correlating with USB/BT/session events.",
                        Confidence = 0.50,
                        Tier = DetectionTier.Tier2Indicator,
                        ProcessName = "SYSTEM",
                        ProcessId = 0,
                        SignalType = SignalType.Generic,
                        AuthorizedResponse = ResponseAction.LogOnly
                    });
                }
            }
        }

        // ─── Detection: New USB Devices ─────────────────────────────────────

        private async Task CheckNewUsbDevicesAsync()
        {
            var current = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            SnapshotUsbDevices(current);

            foreach (var device in current.Except(_baselineUsbDevices))
            {
                // Determine confidence based on whether user is currently idle
                double confidence = _wasIdle ? 0.90 : 0.70;
                string context = _wasIdle
                    ? $" Machine was IDLE (unattended since {_idleStartTime:HH:mm:ss})."
                    : " User appears to be present.";

                if (CanAlert($"USB:{device}"))
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Physical Access: USB Device Inserted",
                        Evidence = $"New USB device at {DateTime.Now:HH:mm:ss}: {device}.{context}",
                        Reasoning = "A USB device was physically connected. If the machine was unattended, this may " +
                                    "indicate unauthorized access (data exfiltration, BadUSB/Rubber Ducky, or keylogger).",
                        Confidence = confidence,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "SYSTEM",
                        ProcessId = 0,
                        SignalType = SignalType.Generic,
                        AuthorizedResponse = ResponseAction.LogOnly
                    });
                }
                _baselineUsbDevices.Add(device);
            }
        }

        // ─── Detection: New Bluetooth Devices ───────────────────────────────

        private async Task CheckNewBluetoothDevicesAsync()
        {
            var current = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            SnapshotBluetoothDevices(current);

            foreach (var device in current.Except(_baselineBluetoothDevices))
            {
                double confidence = _wasIdle ? 0.90 : 0.70;
                string context = _wasIdle
                    ? $" Machine was IDLE (unattended since {_idleStartTime:HH:mm:ss})."
                    : " User appears to be present.";

                if (CanAlert($"BT:{device}"))
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Physical Access: Bluetooth Device Paired",
                        Evidence = $"New Bluetooth device at {DateTime.Now:HH:mm:ss}: {device}.{context}",
                        Reasoning = "A new Bluetooth device was paired with this machine. If the user was away, " +
                                    "this could indicate BadBT HID injection or unauthorized peripheral attachment.",
                        Confidence = confidence,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "SYSTEM",
                        ProcessId = 0,
                        SignalType = SignalType.Generic,
                        AuthorizedResponse = ResponseAction.LogOnly
                    });
                }
                _baselineBluetoothDevices.Add(device);
            }
        }

        // ─── Detection: New Logon Sessions ──────────────────────────────────

        private async Task CheckNewSessionsAsync()
        {
            var current = new HashSet<int>();
            SnapshotSessionIds(current);

            foreach (var sessionId in current.Except(_baselineSessionIds))
            {
                double confidence = _wasIdle ? 0.92 : 0.60;
                string context = _wasIdle
                    ? $" Machine was IDLE (unattended since {_idleStartTime:HH:mm:ss})."
                    : " User appears to be present.";

                if (CanAlert($"Session:{sessionId}"))
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Physical Access: New Logon Session",
                        Evidence = $"New interactive session (ID: {sessionId}) at {DateTime.Now:HH:mm:ss}.{context}",
                        Reasoning = "A new Windows logon session was created. If the machine was unattended, someone " +
                                    "may have logged in without the owner's knowledge.",
                        Confidence = confidence,
                        Tier = DetectionTier.Tier1Behavioral,
                        ProcessName = "winlogon",
                        ProcessId = 0,
                        SignalType = SignalType.Generic,
                        AuthorizedResponse = ResponseAction.LogOnly
                    });
                }
                _baselineSessionIds.Add(sessionId);
            }
        }

        // ─── Utility Methods ────────────────────────────────────────────────

        private static void SnapshotUsbDevices(HashSet<string> target)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USB");
                if (key == null) return;
                foreach (var vidPid in key.GetSubKeyNames())
                {
                    try
                    {
                        using var vidKey = key.OpenSubKey(vidPid);
                        if (vidKey == null) continue;
                        foreach (var serial in vidKey.GetSubKeyNames())
                        {
                            target.Add($"{vidPid}\\{serial}");
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private static void SnapshotBluetoothDevices(HashSet<string> target)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices");
                if (key == null) return;
                foreach (var sub in key.GetSubKeyNames())
                    target.Add(sub);
            }
            catch { }
        }

        private static void SnapshotSessionIds(HashSet<int> target)
        {
            try
            {
                foreach (var proc in Process.GetProcessesByName("explorer"))
                {
                    try { target.Add(proc.SessionId); }
                    catch { }
                    finally { proc.Dispose(); }
                }
            }
            catch { }
        }
    }
}
