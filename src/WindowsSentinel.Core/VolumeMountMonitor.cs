using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Monitors volume mount/dismount events to detect:
    /// - RAM disk creation (ImDisk, OSFMount, SoftPerfect, Arsenal Image Mounter)
    /// - Persistent memory (PMEM/DAX) volume mounts
    /// - VeraCrypt/encrypted container mounts
    /// - VHD/VHDX mounts not initiated by Explorer/DiskMgmt
    /// - Any new volume appearing after service start
    ///
    /// Addresses the blind spot where attackers stage payloads on volatile/unmapped
    /// volumes that FileActivityMonitor doesn't cover.
    ///
    /// v1.0.1: New monitor.
    /// </summary>
    public sealed class VolumeMountMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly FileActivityMonitor _fileActivityMonitor;
        private readonly ILogger<VolumeMountMonitor> _logger;

        private readonly HashSet<string> _baselineVolumes = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, DateTimeOffset> _alertedVolumes = new();

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(5);
        private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(10);

        // Known RAM disk driver device names and service names
        private static readonly HashSet<string> RamDiskDrivers = new(StringComparer.OrdinalIgnoreCase)
        {
            "imdisk", "osfmount", "intmemdrv", "intmemdisk", "intmemsvc",
            "ramdriv", "ramdisk", "vfdwin", "vfd", "dataram", "softperfect",
            "arsenalimager", "aimdevice", "ramphantom", "primo", "primocache",
            "rstmemdrv", "rstmemdsk"
        };

        // Known PMEM/DAX driver names
        private static readonly HashSet<string> PmemDrivers = new(StringComparer.OrdinalIgnoreCase)
        {
            "pmem", "pmemdrv", "nvdimm", "dax", "stornvme_pmem",
            "winpmem", "pmem_memmap"
        };

        // Known encrypted container volume drivers
        private static readonly HashSet<string> EncryptedContainerDrivers = new(StringComparer.OrdinalIgnoreCase)
        {
            "veracrypt", "truecrypt", "bestcrypt", "diskcryptor",
            "pgpdisk", "jetico", "securstar"
        };

        public VolumeMountMonitor(
            DetectionEngine detectionEngine,
            FileActivityMonitor fileActivityMonitor,
            ILogger<VolumeMountMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _fileActivityMonitor = fileActivityMonitor;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[VolumeMountMonitor] Started — scanning for new volume mounts");

            // Baseline current volumes
            foreach (var vol in GetMountedVolumes())
            {
                _baselineVolumes.Add(vol.DeviceId);
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);

                    var currentVolumes = GetMountedVolumes();

                    foreach (var vol in currentVolumes)
                    {
                        if (_baselineVolumes.Contains(vol.DeviceId)) continue;

                        // New volume detected — classify it
                        _baselineVolumes.Add(vol.DeviceId);

                        // Check cooldown
                        if (_alertedVolumes.TryGetValue(vol.DeviceId, out var lastAlert) &&
                            DateTimeOffset.UtcNow - lastAlert < AlertCooldown)
                            continue;

                        _alertedVolumes[vol.DeviceId] = DateTimeOffset.UtcNow;

                        var classification = ClassifyVolume(vol);
                        await EmitVolumeDetection(vol, classification);

                        // Dynamically extend FileActivityMonitor coverage to new volume
                        if (!string.IsNullOrEmpty(vol.DriveLetter))
                        {
                            _fileActivityMonitor.AddWatchPath(vol.DriveLetter);
                            _logger.LogInformation(
                                "[VolumeMountMonitor] Extended FileActivityMonitor to new volume: {Drive}",
                                vol.DriveLetter);
                        }
                    }

                    // Cleanup stale alerts
                    var stale = _alertedVolumes
                        .Where(kv => DateTimeOffset.UtcNow - kv.Value > TimeSpan.FromHours(1))
                        .Select(kv => kv.Key).ToList();
                    foreach (var key in stale) _alertedVolumes.TryRemove(key, out _);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[VolumeMountMonitor] Error"); }
            }
        }

        private async Task EmitVolumeDetection(VolumeInfo vol, VolumeClassification classification)
        {
            var (ruleName, confidence, tier, response, reasoning) = classification switch
            {
                VolumeClassification.RamDisk => (
                    "Volatile Storage: RAM Disk Mounted",
                    0.85,
                    DetectionTier.Tier1Behavioral,
                    ResponseAction.LogOnly,
                    "A RAM disk volume was mounted at runtime. RAM disks are volatile storage that " +
                    "leaves no forensic trace after reboot. Attackers use them to stage payloads, " +
                    "execute malware, and exfiltrate data without touching persistent storage. " +
                    "FileActivityMonitor has been extended to cover this volume."),

                VolumeClassification.PersistentMemory => (
                    "Volatile Storage: PMEM/DAX Volume Mounted",
                    0.88,
                    DetectionTier.Tier1Behavioral,
                    ResponseAction.LogOnly,
                    "A persistent memory (PMEM/DAX) volume was detected. DAX volumes bypass the " +
                    "filesystem cache and provide direct memory-mapped access, making traditional " +
                    "file monitoring ineffective. This is a high-value staging area for sophisticated " +
                    "attackers. FileActivityMonitor has been extended to cover this volume."),

                VolumeClassification.EncryptedContainer => (
                    "Encrypted Volume: Container Mounted",
                    0.70,
                    DetectionTier.Tier2Indicator,
                    ResponseAction.LogOnly,
                    "An encrypted container volume was mounted (VeraCrypt/TrueCrypt/similar). " +
                    "Encrypted containers can hide malware from disk-level scanning. " +
                    "FileActivityMonitor has been extended to cover this volume."),

                VolumeClassification.VirtualDisk => (
                    "Virtual Disk: VHD/VHDX Mounted",
                    0.55,
                    DetectionTier.Tier2Indicator,
                    ResponseAction.LogOnly,
                    "A virtual hard disk (VHD/VHDX) was mounted at runtime. VHDs can contain " +
                    "pre-staged malware that bypasses Mark-of-the-Web. " +
                    "FileActivityMonitor has been extended to cover this volume."),

                _ => (
                    "Storage: New Volume Mounted",
                    0.45,
                    DetectionTier.Tier2Indicator,
                    ResponseAction.LogOnly,
                    "A new storage volume appeared at runtime that was not present at service startup. " +
                    "FileActivityMonitor has been extended to cover this volume.")
            };

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = ruleName,
                Evidence = $"Volume: {vol.DriveLetter ?? vol.DeviceId}, Label: '{vol.Label}', " +
                           $"FileSystem: {vol.FileSystem}, Size: {vol.SizeBytes / (1024 * 1024)}MB, " +
                           $"Driver: {vol.DriverName ?? "unknown"}",
                Reasoning = reasoning,
                Confidence = confidence,
                Tier = tier,
                AuthorizedResponse = response,
                ProcessName = "SYSTEM",
                ProcessId = 0,
                Metadata = new Dictionary<string, string>
                {
                    ["DriveLetter"] = vol.DriveLetter ?? "",
                    ["DeviceId"] = vol.DeviceId,
                    ["FileSystem"] = vol.FileSystem,
                    ["Driver"] = vol.DriverName ?? "",
                    ["Classification"] = classification.ToString(),
                    ["SizeMB"] = (vol.SizeBytes / (1024 * 1024)).ToString()
                }
            });
        }

        private VolumeClassification ClassifyVolume(VolumeInfo vol)
        {
            var driver = vol.DriverName?.ToLowerInvariant() ?? "";
            var deviceId = vol.DeviceId.ToLowerInvariant();
            var label = vol.Label?.ToLowerInvariant() ?? "";

            // Check for RAM disk drivers
            if (RamDiskDrivers.Any(d => driver.Contains(d) || deviceId.Contains(d) || label.Contains(d)))
                return VolumeClassification.RamDisk;

            // Check for PMEM/DAX
            if (PmemDrivers.Any(d => driver.Contains(d) || deviceId.Contains(d)))
                return VolumeClassification.PersistentMemory;

            // Check for encrypted containers
            if (EncryptedContainerDrivers.Any(d => driver.Contains(d) || deviceId.Contains(d)))
                return VolumeClassification.EncryptedContainer;

            // Check for VHD/VHDX based on device path patterns
            if (deviceId.Contains("vhdmp") || deviceId.Contains("vhd") ||
                deviceId.Contains("virtual disk"))
                return VolumeClassification.VirtualDisk;

            // Check DriveType — RAM disks often report as Fixed but have very fast I/O
            // and specific WMI MediaType values
            if (vol.MediaType == "RAM" || vol.MediaType == "Unknown")
                return VolumeClassification.RamDisk;

            return VolumeClassification.Unknown;
        }

        private List<VolumeInfo> GetMountedVolumes()
        {
            var volumes = new List<VolumeInfo>();
            try
            {
                // Use WMI Win32_Volume for comprehensive volume enumeration
                using var searcher = new ManagementObjectSearcher(
                    "SELECT DeviceID, DriveLetter, Label, FileSystem, Capacity, Name FROM Win32_Volume");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var deviceId = obj["DeviceID"]?.ToString() ?? "";
                    var driveLetter = obj["DriveLetter"]?.ToString();
                    var label = obj["Label"]?.ToString() ?? "";
                    var fileSystem = obj["FileSystem"]?.ToString() ?? "";
                    var capacity = obj["Capacity"] != null ? Convert.ToInt64(obj["Capacity"]) : 0;

                    volumes.Add(new VolumeInfo
                    {
                        DeviceId = deviceId,
                        DriveLetter = driveLetter,
                        Label = label,
                        FileSystem = fileSystem,
                        SizeBytes = capacity,
                        DriverName = GetVolumeDriver(deviceId),
                        MediaType = GetMediaType(driveLetter)
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[VolumeMountMonitor] WMI volume query failed");

                // Fallback: use DriveInfo
                try
                {
                    foreach (var drive in DriveInfo.GetDrives())
                    {
                        if (!drive.IsReady) continue;
                        volumes.Add(new VolumeInfo
                        {
                            DeviceId = drive.Name,
                            DriveLetter = drive.Name.TrimEnd('\\'),
                            Label = drive.VolumeLabel,
                            FileSystem = drive.DriveFormat,
                            SizeBytes = drive.TotalSize,
                            MediaType = drive.DriveType.ToString()
                        });
                    }
                }
                catch { }
            }
            return volumes;
        }

        private static string? GetVolumeDriver(string deviceId)
        {
            try
            {
                // Query Win32_PnPEntity for the disk device backing this volume
                using var searcher = new ManagementObjectSearcher(
                    $"ASSOCIATORS OF {{Win32_Volume.DeviceID='{deviceId.Replace("\\", "\\\\")}'}} " +
                    "WHERE AssocClass = Win32_LogicalDiskToPartition");
                foreach (ManagementObject obj in searcher.Get())
                {
                    return obj["Service"]?.ToString();
                }
            }
            catch { }
            return null;
        }

        private static string GetMediaType(string? driveLetter)
        {
            if (string.IsNullOrEmpty(driveLetter)) return "Unknown";
            try
            {
                var drive = new DriveInfo(driveLetter);
                return drive.DriveType switch
                {
                    DriveType.Ram => "RAM",
                    DriveType.Fixed => "Fixed",
                    DriveType.Removable => "Removable",
                    DriveType.Network => "Network",
                    DriveType.CDRom => "CDRom",
                    _ => "Unknown"
                };
            }
            catch { return "Unknown"; }
        }

        private enum VolumeClassification
        {
            Unknown,
            RamDisk,
            PersistentMemory,
            EncryptedContainer,
            VirtualDisk
        }

        private class VolumeInfo
        {
            public string DeviceId { get; set; } = string.Empty;
            public string? DriveLetter { get; set; }
            public string Label { get; set; } = string.Empty;
            public string FileSystem { get; set; } = string.Empty;
            public long SizeBytes { get; set; }
            public string? DriverName { get; set; }
            public string MediaType { get; set; } = "Unknown";
        }
    }
}
