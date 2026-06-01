using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace WindowsSentinel.Core
{
    public class JsonlEventLogger : IAsyncDisposable
    {
        private readonly string _logFilePath;
        private readonly SemaphoreSlim _semaphore = new(1, 1);
        private readonly BurstRateLimiter _rateLimiter = new(100, 200);
        private FileStream? _fileStream;
        private StreamWriter? _writer;
        private bool _isDegraded;

        public JsonlEventLogger(string? customPath = null)
        {
            if (!string.IsNullOrWhiteSpace(customPath))
            {
                _logFilePath = customPath;
            }
            else
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                _logFilePath = Path.Combine(programData, "WindowsSentinel", "events.jsonl");
            }

            // Ensure directory exists
            var directory = Path.GetDirectoryName(_logFilePath);
            if (directory != null && !Directory.Exists(directory))
            {
                try
                {
                    Directory.CreateDirectory(directory);
                }
                catch
                {
                    _isDegraded = true;
                }
            }

            TryOpenFile();
        }

        private void TryOpenFile()
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

                _fileStream = new FileStream(_logFilePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
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
                    _fileStream = new FileStream(_logFilePath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
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

        public async Task LogEventAsync<T>(string type, T data)
        {
            if (!_rateLimiter.AllowRequest())
            {
                // Rate limited, discard or handle
                return;
            }

            await _semaphore.WaitAsync();
            try
            {
                if (_isDegraded || _writer == null)
                {
                    // Self-healing attempt
                    TryOpenFile();
                    if (_isDegraded || _writer == null)
                    {
                        // Still degraded
                        return;
                    }
                }

                // Check file size for rotation (50 MB)
                try
                {
                    if (_fileStream != null && _fileStream.Length > 50 * 1024 * 1024)
                    {
                        RotateLogs();
                    }
                }
                catch
                {
                    // Ignore rotation failure, continue writing
                }

                var entry = new
                {
                    type,
                    timestamp = DateTime.UtcNow,
                    data
                };

                var jsonLine = JsonSerializer.Serialize(entry);
                if (_writer != null)
                {
                    await _writer.WriteLineAsync(jsonLine);
                }
            }
            finally
            {
                _semaphore.Release();
            }
        }

        private void RotateLogs()
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

                TryOpenFile();
            }
            catch
            {
                _isDegraded = true;
            }
        }

        public async ValueTask DisposeAsync()
        {
            await _semaphore.WaitAsync();
            try
            {
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
                _semaphore.Release();
                _semaphore.Dispose();
            }
            GC.SuppressFinalize(this);
        }
    }
}
