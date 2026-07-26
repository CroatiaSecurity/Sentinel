using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Detects PPID spoofing by comparing a process's declared parent PID
    /// (from PROCESS_BASIC_INFORMATION via NtQueryInformationProcess) against
    /// the actual creator PID recorded in the process ancestry cache.
    ///
    /// Installer extractors (Inno Setup, NSIS, etc.) frequently race ETW/WMI
    /// ancestry or re-parent during elevation — that is NOT T1134.004. Killing
    /// them chain-quarantines Git/Chrome/VS installers (observed in production).
    /// </summary>
    public sealed class ParentPidSpoofDetector : IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly AllowlistService _allowlist;
        private readonly SignerTrustService _signerTrust;
        private readonly ILogger<ParentPidSpoofDetector> _logger;
        private readonly System.Threading.Timer _timer;
        private readonly HashSet<int> _alertedPids = new();

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId; // Real parent PID
        }

        private const int ProcessBasicInformation = 0;

        public ParentPidSpoofDetector(
            DetectionEngine de,
            ProcessAncestryCache ac,
            AllowlistService allowlist,
            ILogger<ParentPidSpoofDetector> l,
            SignerTrustService? signerTrust = null)
        {
            _detectionEngine = de;
            _ancestryCache = ac;
            _allowlist = allowlist;
            _signerTrust = signerTrust ?? new SignerTrustService(new Microsoft.Extensions.Logging.Abstractions.NullLogger<SignerTrustService>());
            _logger = l;
            _timer = new System.Threading.Timer(Scan, null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));
        }

        private void Scan(object? state)
        {
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (proc.Id <= 4) continue;
                        if (_alertedPids.Contains(proc.Id)) continue;

                        // Get image path for trust verification (name alone is spoofable)
                        string? imagePath = null;
                        try { imagePath = SecurityValidation.GetProcessImagePath(proc.Id) ?? proc.MainModule?.FileName; }
                        catch { try { imagePath = proc.MainModule?.FileName; } catch { } }

                        // Verify code signature for development tools and browser process exemptions
                        bool isDev = _allowlist.IsDevelopmentProcess(proc.ProcessName);
                        var lowerName = proc.ProcessName.ToLowerInvariant();
                        bool isBrowser = lowerName is "chrome" or "msedge" or "firefox" or "brave" or "opera" or "vivaldi";

                        if (isDev || isBrowser)
                        {
                            // Only skip if the binary is validly signed — no path-based trust
                            if (!string.IsNullOrEmpty(imagePath) && _signerTrust.IsSignedFile(imagePath))
                            {
                                continue;
                            }
                        }

                        // Inno Setup / NSIS / SFX extractors — ancestry races are normal
                        if (InstallerHeuristics.IsInstallerExtractor(proc.ProcessName, imagePath))
                        {
                            continue;
                        }

                        // Signed official installers (Git-2.x-64-bit.exe, etc.)
                        if (!string.IsNullOrEmpty(imagePath) &&
                            InstallerHeuristics.LooksLikeInstallerName(proc.ProcessName, imagePath) &&
                            (SecurityValidation.VerifyAuthenticodeSignature(imagePath) || _signerTrust.IsSignedFile(imagePath)))
                        {
                            continue;
                        }

                        var pbi = new PROCESS_BASIC_INFORMATION();
                        int status = NtQueryInformationProcess(proc.Handle, ProcessBasicInformation,
                            ref pbi, Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _);

                        if (status != 0) continue;

                        int kernelParentPid = (int)pbi.InheritedFromUniqueProcessId;

                        // Compare with what the ancestry cache recorded (from ETW or WMI)
                        var (cachedParentPid, _) = _ancestryCache.GetParent(proc.Id);
                        if (cachedParentPid > 0 && cachedParentPid != kernelParentPid && kernelParentPid > 4)
                        {
                            // Child of a signed installer/extractor → ETW race, not spoofing
                            if (IsBenignInstallerParent(kernelParentPid) || IsBenignInstallerParent(cachedParentPid))
                            {
                                continue;
                            }

                            // Signed process with PPID race: log only — never kill/quarantine chain
                            bool selfSigned = !string.IsNullOrEmpty(imagePath) && _signerTrust.IsSignedFile(imagePath);
                            var response = selfSigned
                                ? ResponseAction.LogOnly
                                : ResponseAction.KillProcess;
                            var tier = selfSigned
                                ? DetectionTier.Tier2Indicator
                                : DetectionTier.Tier1Behavioral;

                            _ = _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "PPID Spoofing: Parent PID Mismatch",
                                Evidence = $"Process '{proc.ProcessName}' (PID {proc.Id}) kernel parent PID={kernelParentPid}, cached parent PID={cachedParentPid}" +
                                           (selfSigned ? " [signed — LogOnly]" : ""),
                                Reasoning = "The process's kernel-reported parent PID does not match the parent recorded via ETW process creation events, indicating PPID spoofing (T1134.004)." +
                                            (selfSigned
                                                ? " Binary is Authenticode-signed; treated as possible ancestry race rather than kill-authorized spoof."
                                                : ""),
                                Confidence = selfSigned ? 0.55 : 0.85,
                                Tier = tier,
                                AuthorizedResponse = response,
                                ProcessName = proc.ProcessName,
                                ProcessId = proc.Id
                            });
                            _alertedPids.Add(proc.Id);
                        }
                    }
                    catch (System.ComponentModel.Win32Exception) { }
                    catch (InvalidOperationException) { }
                    catch { }
                    finally { proc.Dispose(); }
                }

                if (_alertedPids.Count > 500) _alertedPids.Clear();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[ParentPidSpoofDetector] Scan error");
            }
        }

        private bool IsBenignInstallerParent(int parentPid)
        {
            if (parentPid <= 4) return false;
            try
            {
                var procInfo = _ancestryCache.GetProcessInfo(parentPid);
                var name = procInfo.name;
                var path = procInfo.imagePath;
                if (string.IsNullOrEmpty(path))
                    path = SecurityValidation.GetProcessImagePath(parentPid);

                if (InstallerHeuristics.IsInstallerExtractor(name, path)) return true;
                if (InstallerHeuristics.LooksLikeInstallerName(name, path) &&
                    !string.IsNullOrEmpty(path) &&
                    (SecurityValidation.VerifyAuthenticodeSignature(path) || _signerTrust.IsSignedFile(path)))
                    return true;
            }
            catch { }
            return false;
        }

        public void Dispose() => _timer.Dispose();
    }
}
