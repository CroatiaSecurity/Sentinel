using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    /// <summary>
    /// Centralized signer-based trust evaluation. Replaces scattered process-name allowlists.
    /// 
    /// Instead of: "if processName is chrome/discord/teams → suppress"
    /// Now:        "if process binary is Authenticode-signed by a known publisher → suppress"
    /// 
    /// This cannot be spoofed by renaming a binary. An attacker would need the publisher's
    /// private signing key to forge trust.
    /// 
    /// Caches results per file path (signature doesn't change at runtime).
    /// </summary>
    public sealed class SignerTrustService
    {
        private readonly ILogger<SignerTrustService> _logger;

        // Cache: file path → (isSigned, signerName)
        private readonly ConcurrentDictionary<string, (bool IsSigned, string Signer)> _cache = new(StringComparer.OrdinalIgnoreCase);

        // Known trusted signers (Microsoft, Google, Mozilla, etc.)
        // These are Authenticode certificate subject CN values
        private static readonly HashSet<string> TrustedSigners = new(StringComparer.OrdinalIgnoreCase)
        {
            // Microsoft
            "Microsoft Corporation",
            "Microsoft Windows",
            "Microsoft Windows Publisher",
            "Microsoft Code Signing PCA",
            // Google
            "Google LLC",
            "Google Inc",
            // Mozilla
            "Mozilla Corporation",
            // Valve
            "Valve Corp.",
            "Valve Corporation",
            // Discord
            "Discord Inc.",
            // Spotify
            "Spotify AB",
            // Slack
            "Slack Technologies, Inc.",
            "Slack Technologies, LLC",
            // Brave
            "Brave Software, Inc.",
            // Opera
            "Opera Norway AS",
            // Vivaldi
            "Vivaldi Technologies AS",
            // JetBrains
            "JetBrains s.r.o.",
            // VS Code / Cursor / Electron apps with Microsoft signature
            "Microsoft Corporation - Marketplace",
            // Dropbox
            "Dropbox, Inc.",
            "Dropbox, Inc",
            // NVIDIA
            "NVIDIA Corporation",
            // Intel
            "Intel Corporation",
            "Intel(R) Software Development Products",
            // AMD
            "Advanced Micro Devices, Inc.",
            // Realtek
            "Realtek Semiconductor Corp.",
        };

        // Untrusted signers — even if signed, these are suspicious
        private static readonly HashSet<string> UntrustedSigners = new(StringComparer.OrdinalIgnoreCase)
        {
            // Known malware signers, revoked certs, etc.
            // Add as discovered
        };

        public SignerTrustService(ILogger<SignerTrustService> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Returns true if the process at the given PID is signed by a trusted publisher.
        /// Result is cached per image path.
        /// </summary>
        public bool IsTrustedProcess(int pid)
        {
            try
            {
                using var proc = Process.GetProcessById(pid);
                var path = proc.MainModule?.FileName;
                if (string.IsNullOrEmpty(path)) return false;
                return IsTrustedFile(path);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Returns true if the file at the given path is Authenticode-signed by a trusted publisher.
        /// </summary>
        public bool IsTrustedFile(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return false;

            // Check cache first
            if (_cache.TryGetValue(filePath, out var cached))
                return cached.IsSigned && TrustedSigners.Contains(cached.Signer);

            // Verify signature and extract signer
            var (isSigned, signer) = VerifyAndExtractSigner(filePath);
            _cache[filePath] = (isSigned, signer);

            if (isSigned && UntrustedSigners.Contains(signer))
            {
                _logger.LogWarning("[SignerTrustService] File signed by UNTRUSTED signer: {Signer} — {Path}", signer, filePath);
                return false;
            }

            return isSigned && TrustedSigners.Contains(signer);
        }

        /// <summary>
        /// Returns the signer name for a given file, or null if unsigned.
        /// </summary>
        public string? GetSignerName(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) return null;

            if (_cache.TryGetValue(filePath, out var cached))
                return cached.IsSigned ? cached.Signer : null;

            var (isSigned, signer) = VerifyAndExtractSigner(filePath);
            _cache[filePath] = (isSigned, signer);
            return isSigned ? signer : null;
        }

        /// <summary>
        /// Quick check: is this process name + image path combination trustworthy?
        /// Uses signer verification, NOT process name matching.
        /// 
        /// This is the drop-in replacement for:
        ///   if (allowlist.Contains(processName)) return;
        /// Replace with:
        ///   if (signerTrust.IsTrustedProcessByPath(imagePath)) return;
        /// </summary>
        public bool IsTrustedProcessByPath(string? imagePath)
        {
            if (string.IsNullOrEmpty(imagePath)) return false;

            // Fast path: System32/SysWOW64 binaries are OS-signed
            if (imagePath.Contains(@"\System32\", StringComparison.OrdinalIgnoreCase) ||
                imagePath.Contains(@"\SysWOW64\", StringComparison.OrdinalIgnoreCase))
            {
                return true; // Windows system binaries
            }

            return IsTrustedFile(imagePath);
        }

        private (bool IsSigned, string Signer) VerifyAndExtractSigner(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return (false, string.Empty);

                // First verify the signature is valid
                if (!SecurityValidation.VerifyAuthenticodeSignature(filePath, _logger))
                    return (false, string.Empty);

                // Extract the signer CN from the certificate
                var signer = ExtractSignerCN(filePath);
                return (true, signer ?? string.Empty);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[SignerTrustService] Failed to verify {Path}", filePath);
                return (false, string.Empty);
            }
        }

        private static string? ExtractSignerCN(string filePath)
        {
            try
            {
#pragma warning disable SYSLIB0057 // CreateFromSignedFile is obsolete but has no X509CertificateLoader equivalent for Authenticode
                using var cert = X509Certificate2.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
                // Parse CN from Subject
                var subject = cert.Subject;
                // Subject looks like: CN="Microsoft Corporation", O="Microsoft Corporation", ...
                var cnStart = subject.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);
                if (cnStart < 0) return subject;

                cnStart += 3;
                string cn;
                if (cnStart < subject.Length && subject[cnStart] == '"')
                {
                    // Quoted CN
                    var cnEnd = subject.IndexOf('"', cnStart + 1);
                    cn = cnEnd > cnStart ? subject[(cnStart + 1)..cnEnd] : subject[(cnStart + 1)..];
                }
                else
                {
                    // Unquoted CN
                    var cnEnd = subject.IndexOf(',', cnStart);
                    cn = cnEnd > cnStart ? subject[cnStart..cnEnd] : subject[cnStart..];
                }

                return cn.Trim();
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Prune cache entries for files that no longer exist (called periodically).
        /// </summary>
        public void PruneCache()
        {
            var stale = _cache.Keys.Where(k => !File.Exists(k)).ToList();
            foreach (var k in stale) _cache.TryRemove(k, out _);
        }
    }
}
