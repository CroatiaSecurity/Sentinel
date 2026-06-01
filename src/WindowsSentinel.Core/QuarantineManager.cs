using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace WindowsSentinel.Core
{
    public class QuarantineManager
    {
        private readonly string _quarantineDir;
        private static readonly Regex MetadataRegex = new(@"^q_([a-fA-F0-9]+)_([a-zA-Z0-9_\-\s]+)$", RegexOptions.Compiled);

        public QuarantineManager(string? customPath = null)
        {
            if (!string.IsNullOrWhiteSpace(customPath))
            {
                _quarantineDir = customPath;
            }
            else
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                _quarantineDir = Path.Combine(programData, "WindowsSentinel", "Quarantine");
            }

            if (!Directory.Exists(_quarantineDir))
            {
                Directory.CreateDirectory(_quarantineDir);
            }
        }

        public async Task<string> QuarantineFileAtomicAsync(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("File not found for quarantine", filePath);
            }

            var fileBytes = await File.ReadAllBytesAsync(filePath);
            
            // Encrypt using XOR 0x5A for simple quarantine isolation
            for (int i = 0; i < fileBytes.Length; i++)
            {
                fileBytes[i] = (byte)(fileBytes[i] ^ 0x5A);
            }

            var fileName = Path.GetFileName(filePath);
            var safeName = Regex.Replace(fileName, @"[^a-zA-Z0-9_\-\.]", "_");
            var uniqueId = Guid.NewGuid().ToString("N");
            
            // Format: q_<uniqueId>_<safeName>
            var quarantineFileName = $"q_{uniqueId}_{safeName}";
            var tempPath = Path.Combine(_quarantineDir, $"{quarantineFileName}.tmp");
            var finalPath = Path.Combine(_quarantineDir, quarantineFileName);

            // Write, move, and delete source atomically
            await File.WriteAllBytesAsync(tempPath, fileBytes);
            
            if (File.Exists(finalPath))
            {
                File.Delete(finalPath);
            }
            File.Move(tempPath, finalPath);

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
