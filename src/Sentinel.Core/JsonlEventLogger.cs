using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    public class JsonlEventLogger : IAsyncDisposable
    {
        private readonly string _logFilePath;
        private readonly SemaphoreSlim _semaphore = new(1, 1);
        private readonly BurstRateLimiter _rateLimiter = new(1000, 5000);
        private FileStream? _fileStream;
        private StreamWriter? _writer;
        private bool _isDegraded;
        private bool _diskSpaceDegraded;
        private bool _disposed;

        public string LogFilePath => _logFilePath;
        private long _droppedEvents;
        public long DroppedEvents => Interlocked.Read(ref _droppedEvents);

        public JsonlEventLogger(string? customPath = null)
        {
            if (!string.IsNullOrWhiteSpace(customPath))
            {
                _logFilePath = customPath;
            }
            else
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                _logFilePath = Path.Combine(programData, "Sentinel", "events.jsonl");
            }

            // Ensure directory exists
            var directory = Path.GetDirectoryName(_logFilePath);
            if (directory != null)
            {
                try
                {
                    if (!Directory.Exists(directory))
                    {
                        Directory.CreateDirectory(directory);
                    }

                    // Only apply production ACLs if this is the default production path in CommonApplicationData
                    var prodDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel");
                    if (directory.StartsWith(prodDir))
                    {
                        // Restrict log directory ACLs to SYSTEM and Administrators (Full) and Users (Read-Only)
                        var dirInfo = new DirectoryInfo(directory);
                        var security = dirInfo.GetAccessControl();
                        security.SetAccessRuleProtection(true, false);
                        var systemSid = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
                        security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(systemSid, System.Security.AccessControl.FileSystemRights.FullControl, System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
                        var adminSid = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
                        security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(adminSid, System.Security.AccessControl.FileSystemRights.FullControl, System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
                        var usersSid = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);
                        security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(usersSid, System.Security.AccessControl.FileSystemRights.Read, System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
                        dirInfo.SetAccessControl(security);
                    }
                }
                catch
                {
                    _isDegraded = true;
                }
            }

            TryOpenFileInternal();
        }

        private void TryOpenFileInternal()
        {
            try
            {
                if (_writer != null)
                {
                    _writer.Dispose();
                    _writer = null;
                }
                if (_fileStream != null)
                {
                    _fileStream.Dispose();
                    _fileStream = null;
                }

                _fileStream = new FileStream(_logFilePath, FileMode.Append, FileAccess.Write,
                    FileShare.ReadWrite | FileShare.Delete);
                _writer = new StreamWriter(_fileStream) { AutoFlush = true };
                _isDegraded = false;
            }
            catch (IOException)
            {
                // Stale file handling: try renaming locked/inaccessible file to .stale.<timestamp>
                try
                {
                    var stalePath = $"{_logFilePath}.stale.{DateTime.UtcNow:yyyyMMddHHmmss}";
                    if (File.Exists(_logFilePath))
                    {
                        File.Move(_logFilePath, stalePath);
                    }
                    _fileStream = new FileStream(_logFilePath, FileMode.Create, FileAccess.Write,
                        FileShare.ReadWrite | FileShare.Delete);
                    _writer = new StreamWriter(_fileStream) { AutoFlush = true };
                    _isDegraded = false;
                }
                catch
                {
                    _isDegraded = true;
                }
            }
            catch
            {
                _isDegraded = true;
            }
        }

        public async Task LogEventAsync<T>(string type, T data, CancellationToken cancellationToken = default)
        {
            if (!_rateLimiter.AllowRequest())
            {
                Interlocked.Increment(ref _droppedEvents);
                return;
            }

            if (_disposed)
                return;

            try
            {
                await _semaphore.WaitAsync(cancellationToken);
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (OperationCanceledException)
            {
                throw;
            }

            try
            {
                if (_disposed)
                    return;

                if (_isDegraded || _writer == null)
                {
                    // Self-healing attempt
                    TryOpenFileInternal();
                    if (_isDegraded || _writer == null)
                    {
                        // Still degraded
                        return;
                    }
                }

                // Check file size for rotation (20 MB — keep I/O and dashboard reads lighter)
                try
                {
                    if (_fileStream != null && _fileStream.Length > 20L * 1024 * 1024)
                    {
                        RotateLogsInternal();
                    }
                }
                catch
                {
                    // Ignore rotation failure, continue writing
                }

                // v2.0.3: Disk space guard — degrade gracefully if volume is critically low.
                // Prevents Sentinel from filling the last remaining disk space with event logs.
                if (!CheckDiskSpaceInternal())
                {
                    Interlocked.Increment(ref _droppedEvents);
                    return;
                }

                var entry = new
                {
                    type,
                    timestamp = DateTime.UtcNow,
                    data
                };

                string jsonLine;
                try
                {
                    jsonLine = JsonSerializer.Serialize(entry);
                }
                catch
                {
                    // Fallback: serialize with type name and error indicator
                    jsonLine = JsonSerializer.Serialize(new { type, timestamp = DateTime.UtcNow, data = $"<unserializable:{typeof(T).Name}>" });
                }

                if (_writer != null)
                {
                    await _writer.WriteLineAsync(jsonLine);
                }
            }
            finally
            {
                try { _semaphore.Release(); } catch (ObjectDisposedException) { }
            }
        }

        /// <summary>
        /// v2.0.3: Check available disk space on the log volume.
        /// Returns false (skip write) when free space is below 100 MB.
        /// Also triggers cleanup of oldest rotated logs to reclaim space.
        /// </summary>
        private bool CheckDiskSpaceInternal()
        {
            try
            {
                var logDir = Path.GetDirectoryName(_logFilePath);
                if (string.IsNullOrEmpty(logDir)) return true;

                var driveRoot = Path.GetPathRoot(logDir);
                if (string.IsNullOrEmpty(driveRoot)) return true;

                var driveInfo = new DriveInfo(driveRoot);
                if (!driveInfo.IsReady) return true;

                long freeBytes = driveInfo.AvailableFreeSpace;
                const long MinFreeBytes = 100L * 1024 * 1024; // 100 MB floor
                const long WarnFreeBytes = 200L * 1024 * 1024; // 200 MB → prune old logs

                if (freeBytes < WarnFreeBytes)
                {
                    // Proactively delete oldest rotated logs to reclaim space
                    PruneOldestRotatedLogs();
                }

                if (freeBytes < MinFreeBytes)
                {
                    // Critical: stop writing to prevent disk exhaustion
                    if (!_isDegraded)
                    {
                        _isDegraded = true;
                        _diskSpaceDegraded = true;
                    }
                    return false;
                }

                // Recover from disk-space degradation if space freed up
                if (_diskSpaceDegraded && freeBytes >= MinFreeBytes)
                {
                    _diskSpaceDegraded = false;
                    if (_isDegraded)
                    {
                        TryOpenFileInternal();
                    }
                }

                return true;
            }
            catch
            {
                // Cannot determine disk space — allow write (fail-open for logging)
                return true;
            }
        }

        /// <summary>
        /// v2.0.3: Delete the oldest rotated log files when disk space is low.
        /// Deletes from .5 down to .3 (keeps .1 and .2 as recent context).
        /// </summary>
        private void PruneOldestRotatedLogs()
        {
            try
            {
                for (int i = 5; i >= 3; i--)
                {
                    var rotatedPath = $"{_logFilePath}.{i}";
                    if (File.Exists(rotatedPath))
                    {
                        File.Delete(rotatedPath);
                    }
                }
            }
            catch { /* best effort */ }
        }

        private void RotateLogsInternal()
        {
            try
            {
                if (_writer != null)
                {
                    _writer.Dispose();
                    _writer = null;
                }
                if (_fileStream != null)
                {
                    _fileStream.Dispose();
                    _fileStream = null;
                }

                // Rotate events.jsonl.4 -> events.jsonl.5, etc.
                for (int i = 4; i >= 1; i--)
                {
                    var oldPath = $"{_logFilePath}.{i}";
                    var newPath = $"{_logFilePath}.{i + 1}";
                    if (File.Exists(oldPath))
                    {
                        if (File.Exists(newPath)) File.Delete(newPath);
                        File.Move(oldPath, newPath);
                    }
                }

                if (File.Exists(_logFilePath))
                {
                    var backupPath = $"{_logFilePath}.1";
                    if (File.Exists(backupPath)) File.Delete(backupPath);
                    File.Move(_logFilePath, backupPath);
                }

                TryOpenFileInternal();
            }
            catch
            {
                _isDegraded = true;
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (_disposed)
                return;

            try
            {
                await _semaphore.WaitAsync();
            }
            catch (ObjectDisposedException)
            {
                return;
            }

            try
            {
                _disposed = true;
                if (_writer != null)
                {
                    await _writer.DisposeAsync();
                    _writer = null;
                }
                if (_fileStream != null)
                {
                    await _fileStream.DisposeAsync();
                    _fileStream = null;
                }
            }
            finally
            {
                try { _semaphore.Release(); } catch (ObjectDisposedException) { }
                _semaphore.Dispose();
            }
            GC.SuppressFinalize(this);
        }
    }
}
