using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    public class QuarantineManager
    {
        private readonly string _quarantineDir;
        private static readonly Regex MetadataRegex = new(@"^q_([a-fA-F0-9]+)_([a-zA-Z0-9_\-\s\.]+)$", RegexOptions.Compiled);

        public string QuarantineDirectory => _quarantineDir;

        public QuarantineManager(string? customPath = null)
        {
            if (!string.IsNullOrWhiteSpace(customPath))
            {
                _quarantineDir = customPath;
            }
            else
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                _quarantineDir = Path.Combine(programData, "Sentinel", "Quarantine");
            }

            // Only create the directory if we have access (Service runs as SYSTEM, Agent as user).
            // The Agent doesn't write to quarantine — the Service handles all quarantine operations.
            try
            {
                if (!Directory.Exists(_quarantineDir))
                {
                    Directory.CreateDirectory(_quarantineDir);
                }
            }
            catch (UnauthorizedAccessException)
            {
                // Running as user-session Agent — quarantine dir is owned by SYSTEM.
                // This is expected; the Agent only reads quarantine metadata for display.
            }
        }

        /// <summary>
        /// Quarantines a file (DPAPI-encrypt, move to quarantine, delete original).
        ///
        /// By default, <b>refuses Authenticode-signed binaries</b> — official installers
        /// (Git for Windows, ChromeSetup, VS Code, etc.) must not be destroyed on disk
        /// by chain-trace FPs. Kill-process is still allowed by callers; only quarantine
        /// is blocked. Pass <paramref name="forceQuarantineSigned"/> only for deliberate
        /// impostor/sideload remediation where the signed file is known-bad in context.
        ///
        /// Returns the quarantine path, or <c>null</c> if the file was refused (signed)
        /// or missing.
        /// </summary>
        public async Task<string?> QuarantineFileAtomicAsync(string filePath, bool forceQuarantineSigned = false)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("File not found for quarantine", filePath);
            }

            // Central gate: never wipe signed software unless explicitly forced.
            // Covers ChainTracer, IncidentResponse, QuarantineAndKill, and any future caller.
            if (!forceQuarantineSigned)
            {
                try
                {
                    if (SecurityValidation.VerifyAuthenticodeSignature(filePath))
                    {
                        return null; // preserved on disk
                    }
                }
                catch
                {
                    // Signature check failed open → treat as unsigned and proceed
                }
            }

            // Read with FileShare.Delete — never block user from deleting files
            byte[] fileBytes;
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete))
            {
                fileBytes = new byte[fs.Length];
                await fs.ReadExactlyAsync(fileBytes);
            }

            // Encrypt using DPAPI (machine-scoped) for quarantine isolation
            fileBytes = ProtectedData.Protect(fileBytes, null, DataProtectionScope.LocalMachine);

            var fileName = Path.GetFileName(filePath);
            var safeName = Regex.Replace(fileName, @"[^a-zA-Z0-9_\-\.]", "_");
            var uniqueId = Guid.NewGuid().ToString("N");

            // Format: q_<uniqueId>_<safeName>
            // Also store original full path in a sibling .meta file for restore.
            var quarantineFileName = $"q_{uniqueId}_{safeName}";
            var tempPath = Path.Combine(_quarantineDir, $"{quarantineFileName}.tmp");
            var finalPath = Path.Combine(_quarantineDir, quarantineFileName);
            var metaPath = Path.Combine(_quarantineDir, $"{quarantineFileName}.meta");

            // Write, move, and delete source atomically
            await File.WriteAllBytesAsync(tempPath, fileBytes);

            if (File.Exists(finalPath))
            {
                File.Delete(finalPath);
            }
            File.Move(tempPath, finalPath);

            try
            {
                await File.WriteAllTextAsync(metaPath, filePath);
            }
            catch { /* restore still possible by filename guess */ }

            // Remove original attributes and delete
            try
            {
                File.SetAttributes(filePath, FileAttributes.Normal);
                File.Delete(filePath);
            }
            catch (IOException)
            {
                // Retry deletion
                await Task.Delay(100);
                File.Delete(filePath);
            }

            return finalPath;
        }

        /// <summary>
        /// Lists quarantine entries (encrypted blob filename + optional original path from .meta).
        /// </summary>
        public IReadOnlyList<(string QuarantineFile, string? OriginalPath, string DisplayName)> ListQuarantined()
        {
            var results = new List<(string, string?, string)>();
            try
            {
                if (!Directory.Exists(_quarantineDir)) return results;
                foreach (var file in Directory.EnumerateFiles(_quarantineDir))
                {
                    var name = Path.GetFileName(file);
                    if (name.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase) ||
                        name.EndsWith(".meta", StringComparison.OrdinalIgnoreCase))
                        continue;
                    if (!name.StartsWith("q_", StringComparison.OrdinalIgnoreCase))
                        continue;

                    string? original = null;
                    var meta = file + ".meta";
                    if (File.Exists(meta))
                    {
                        try { original = File.ReadAllText(meta).Trim(); } catch { }
                    }

                    ParseQuarantineMetadata(name, out _, out var display);
                    if (string.IsNullOrEmpty(display)) display = name;
                    results.Add((file, original, display));
                }
            }
            catch { }
            return results;
        }

        /// <summary>
        /// Restores a quarantined file to <paramref name="destinationPath"/> (or the path
        /// recorded in the .meta sidecar). Decrypts DPAPI machine-scope blob.
        /// </summary>
        public async Task<string> RestoreAsync(string quarantineFilePath, string? destinationPath = null)
        {
            if (!File.Exists(quarantineFilePath))
                throw new FileNotFoundException("Quarantine file not found", quarantineFilePath);

            if (string.IsNullOrEmpty(destinationPath))
            {
                var meta = quarantineFilePath + ".meta";
                if (File.Exists(meta))
                {
                    destinationPath = (await File.ReadAllTextAsync(meta)).Trim();
                }
                else
                {
                    ParseQuarantineMetadata(Path.GetFileName(quarantineFilePath), out _, out var originalName);
                    if (string.IsNullOrEmpty(originalName))
                        throw new InvalidOperationException("No restore path recorded and could not parse original name.");
                    destinationPath = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                        "Downloads",
                        originalName);
                }
            }

            var encrypted = await File.ReadAllBytesAsync(quarantineFilePath);
            var plain = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.LocalMachine);

            var destDir = Path.GetDirectoryName(destinationPath);
            if (!string.IsNullOrEmpty(destDir) && !Directory.Exists(destDir))
                Directory.CreateDirectory(destDir);

            await File.WriteAllBytesAsync(destinationPath, plain);

            try
            {
                File.Delete(quarantineFilePath);
                var meta = quarantineFilePath + ".meta";
                if (File.Exists(meta)) File.Delete(meta);
            }
            catch { }

            return destinationPath;
        }

        public bool ParseQuarantineMetadata(string quarantineFileName, out string uniqueId, out string originalName)
        {
            uniqueId = string.Empty;
            originalName = string.Empty;

            var match = MetadataRegex.Match(quarantineFileName);
            if (match.Success && match.Groups.Count == 3)
            {
                uniqueId = match.Groups[1].Value;
                originalName = match.Groups[2].Value;
                return true;
            }
            return false;
        }
    }
}
