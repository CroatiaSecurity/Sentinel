using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;

namespace WindowsSentinel.Core.Monitors;

/// <summary>
/// Monitors file system activity using FileSystemWatcher.
/// Detects ransomware-like bulk rename/write patterns.
/// </summary>
public sealed class FileActivityMonitor : IMonitor
{
    public string Name => "File Activity Monitor";

    private readonly IDetectionEngine _detectionEngine;
    private readonly ILogger<FileActivityMonitor> _logger;
    private readonly string _watchPath;
    private readonly TelemetryFusionEngine? _fusionEngine;
    private FileSystemWatcher? _watcher;

    // Sliding window: track rename events per process (approximated by path)
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> _renameCount = new();
    private DateTimeOffset _windowStart = DateTimeOffset.UtcNow;
    private const int RansomwareRenameThreshold = 20;
    private const int WindowSeconds = 10;

    // Comprehensive ransomware extension list — covers major families:
    // WannaCry, Locky, Cerber, REvil/Sodinokibi, LockBit, BlackCat/ALPHV,
    // Conti, Ryuk, DarkSide, Maze, NetWalker, Dharma, Phobos, Stop/DJVU, and more.
    private static readonly HashSet<string> RansomwareExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        // Generic / multi-family
        ".locked", ".encrypted", ".enc", ".crypt", ".crypted", ".crypto",
        ".encrypt", ".lock", ".locked1",
        // WannaCry / WannaCrypt
        ".wnry", ".wncry", ".wcry", ".wncrypt",
        // Locky family
        ".locky", ".zepto", ".odin", ".aesir", ".thor", ".zzzzz",
        // Cerber
        ".cerber", ".cerber2", ".cerber3",
        // CryptoLocker / CryptoWall
        ".ccc", ".vvv", ".exx", ".ezz", ".ecc", ".abc", ".xyz", ".zzz",
        ".aaa", ".bbb", ".micro", ".xxx",
        // Dharma / Crysis
        ".dharma", ".wallet", ".onion", ".arena", ".cobra", ".java",
        ".adobe", ".bip", ".cmb", ".combo", ".AUDIT",
        // Phobos
        ".phobos", ".eking", ".eight", ".help",
        // Stop / DJVU
        ".stop", ".djvu", ".djvuu", ".udjvu", ".puma", ".pumax", ".uudjvu",
        ".tfude", ".tfudet", ".tfudeq", ".rumba", ".adobe", ".tro",
        // REvil / Sodinokibi
        ".sodinokibi", ".reven",
        // LockBit
        ".lockbit", ".abcd",
        // BlackCat / ALPHV
        ".alphv",
        // Maze
        ".maze",
        // NetWalker
        ".netwalker",
        // Ryuk
        ".ryk", ".ryuk",
        // DarkSide
        ".darkside",
        // Conti
        ".conti",
        // Hive
        ".hive",
        // BlackMatter
        ".blackmatter",
        // AvosLocker
        ".avos", ".avos2",
        // Grief / PayOrGrief
        ".grief",
        // Karma
        ".karma",
        // Clop
        ".clop",
        // Egregor
        ".egregor",
        // Babuk
        ".babuk",
        // Cuba
        ".cuba",
        // Vice Society
        ".v-society",
        // Generic patterns used by custom ransomware
        ".pay2decrypt", ".paydecrypt", ".decrypt2017",
        ".cryptolocker", ".cryptowall",
    };

    public FileActivityMonitor(
        IDetectionEngine detectionEngine,
        ILogger<FileActivityMonitor> logger,
        string? watchPath = null,
        TelemetryFusionEngine? fusionEngine = null)
    {
        _detectionEngine = detectionEngine;
        _logger          = logger;
        _watchPath       = watchPath ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        _fusionEngine    = fusionEngine;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("[{Monitor}] Watching '{Path}'.", Name, _watchPath);

        _watcher = new FileSystemWatcher(_watchPath)
        {
            IncludeSubdirectories = true,
            NotifyFilter          = NotifyFilters.FileName | NotifyFilters.LastWrite,
            EnableRaisingEvents   = true
        };

        _watcher.Renamed += async (_, e) =>
        {
            if (cancellationToken.IsCancellationRequested) return;
            await HandleRenameAsync(e, cancellationToken);
        };

        _watcher.Error += (_, e) =>
            _logger.LogError(e.GetException(), "[{Monitor}] FileSystemWatcher error.", Name);

        return Task.CompletedTask;
    }

    private async Task HandleRenameAsync(RenamedEventArgs e, CancellationToken cancellationToken)
    {
        try
        {
            var newExt = Path.GetExtension(e.FullPath);
            bool isSuspiciousExt = RansomwareExtensions.Contains(newExt);

            // Reset sliding window
            if ((DateTimeOffset.UtcNow - _windowStart).TotalSeconds > WindowSeconds)
            {
                _renameCount.Clear();
                _windowStart = DateTimeOffset.UtcNow;
            }

            var dir = Path.GetDirectoryName(e.FullPath) ?? e.FullPath;
            _renameCount.AddOrUpdate(dir, 1, (_, c) => c + 1);

            bool bulkRename = _renameCount.Values.Sum() >= RansomwareRenameThreshold;

            if (isSuspiciousExt || bulkRename)
            {
                // Feed telemetry fusion engine (enriches event graph)
                _fusionEngine?.IngestFileActivity(0, "Unknown",
                    e.FullPath, Engine.FileActivityKind.Rename, DateTimeOffset.UtcNow);

                var telemetry = new FileActivityTelemetry
                {
                    OldPath    = e.OldFullPath,
                    NewPath    = e.FullPath,
                    IsSuspiciousExtension = isSuspiciousExt,
                    IsBulkRename = bulkRename,
                    RenameCount  = _renameCount.Values.Sum(),
                    Timestamp    = DateTimeOffset.UtcNow
                };
                await _detectionEngine.ProcessAsync(telemetry, cancellationToken);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "[{Monitor}] Error handling rename event.", Name);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("[{Monitor}] Stopping.", Name);
        _watcher?.Dispose();
        return Task.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        _watcher?.Dispose();
        return ValueTask.CompletedTask;
    }
}

public sealed class FileActivityTelemetry
{
    public required string OldPath              { get; init; }
    public required string NewPath              { get; init; }
    public required bool   IsSuspiciousExtension { get; init; }
    public required bool   IsBulkRename         { get; init; }
    public required int    RenameCount          { get; init; }
    public required DateTimeOffset Timestamp    { get; init; }
    public Dictionary<string, string> Metadata  { get; init; } = new();
}

