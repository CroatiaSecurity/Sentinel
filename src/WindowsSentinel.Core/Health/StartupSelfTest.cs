using System.Security.Cryptography;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;
using WindowsSentinel.Core.Interfaces;

namespace WindowsSentinel.Core.Health;

/// <summary>
/// Startup Self-Test — Verifies critical subsystems on service start.
///
/// Checks performed:
///   1. ETW session creation (can we actually trace?)
///   2. DPAPI round-trip (encrypt → decrypt)
///   3. Quarantine directory is writable
///   4. Log file is writable
///   5. At least one detection rule loaded
///
/// If any check fails, a clear error is logged explaining what's wrong.
/// The service continues running (degraded) rather than crashing — but
/// operators get immediate visibility into what's broken.
/// </summary>
public sealed class StartupSelfTest
{
    private readonly ILogger<StartupSelfTest> _logger;
    private readonly IEnumerable<IDetectionRule> _rules;
    private readonly string _logPath;
    private readonly string _quarantinePath;

    public StartupSelfTest(
        ILogger<StartupSelfTest> logger,
        IEnumerable<IDetectionRule> rules,
        string logPath)
    {
        _logger = logger;
        _rules = rules;
        _logPath = logPath;
        _quarantinePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "WindowsSentinel", "Quarantine");
    }

    /// <summary>
    /// Runs all self-test checks and returns a summary result.
    /// Each check is independent — a failure in one does not prevent others from running.
    /// </summary>
    public SelfTestResult RunAll()
    {
        _logger.LogInformation("=== Startup Self-Test beginning ===");

        var result = new SelfTestResult();

        result.EtwAvailable = TestEtwSession();
        result.DpapiAvailable = TestDpapi();
        result.QuarantineWritable = TestQuarantineDirectory();
        result.LogFileWritable = TestLogFile();
        result.RulesLoaded = TestDetectionRules();

        var passed = result.PassedCount;
        var total = result.TotalChecks;

        if (result.AllPassed)
        {
            _logger.LogInformation(
                "=== Startup Self-Test PASSED ({Passed}/{Total}) — all subsystems operational ===",
                passed, total);
        }
        else
        {
            _logger.LogError(
                "=== Startup Self-Test DEGRADED ({Passed}/{Total}) — some subsystems failed ===",
                passed, total);
        }

        return result;
    }

    private bool TestEtwSession()
    {
        const string testSessionName = "WindowsSentinel-SelfTest";
        try
        {
            // Attempt to create and immediately dispose an ETW session
            using var session = new TraceEventSession(testSessionName);
            session.Stop();
            _logger.LogInformation("[SelfTest] ETW session creation: OK");
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            _logger.LogError(
                "[SelfTest] ETW session creation: FAILED — insufficient privileges. " +
                "The service must run as SYSTEM or an account with SeSystemProfilePrivilege.");
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "[SelfTest] ETW session creation: FAILED — {Message}", ex.Message);
            return false;
        }
        finally
        {
            // Clean up any orphaned test session
            try { TraceEventSession.GetActiveSession(testSessionName)?.Stop(); } catch { }
        }
    }

    private bool TestDpapi()
    {
        try
        {
            // Round-trip test: encrypt then decrypt a known payload
            var testData = System.Text.Encoding.UTF8.GetBytes("SentinelSelfTest");
            var encrypted = ProtectedData.Protect(testData, null, DataProtectionScope.LocalMachine);
            var decrypted = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.LocalMachine);

            if (testData.AsSpan().SequenceEqual(decrypted))
            {
                _logger.LogInformation("[SelfTest] DPAPI round-trip: OK");
                return true;
            }

            _logger.LogError("[SelfTest] DPAPI round-trip: FAILED — decrypted data does not match original.");
            return false;
        }
        catch (CryptographicException ex)
        {
            _logger.LogError(ex,
                "[SelfTest] DPAPI round-trip: FAILED — CryptographicException. " +
                "This may indicate the DPAPI master key is unavailable or the service " +
                "account lacks access to the machine key store.");
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[SelfTest] DPAPI round-trip: FAILED — {Message}", ex.Message);
            return false;
        }
    }

    private bool TestQuarantineDirectory()
    {
        try
        {
            Directory.CreateDirectory(_quarantinePath);

            // Write and delete a test file to verify write access
            var testFile = Path.Combine(_quarantinePath, ".selftest");
            File.WriteAllText(testFile, "selftest");
            File.Delete(testFile);

            _logger.LogInformation("[SelfTest] Quarantine directory writable: OK ({Path})", _quarantinePath);
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            _logger.LogError(
                "[SelfTest] Quarantine directory: FAILED — access denied to {Path}. " +
                "Ensure the service account has write access to the quarantine directory.",
                _quarantinePath);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "[SelfTest] Quarantine directory: FAILED — cannot write to {Path}", _quarantinePath);
            return false;
        }
    }

    private bool TestLogFile()
    {
        try
        {
            var logDir = Path.GetDirectoryName(_logPath);
            if (!string.IsNullOrEmpty(logDir))
                Directory.CreateDirectory(logDir);

            // Append a zero-length write to verify access (don't corrupt existing log)
            using var fs = new FileStream(_logPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite);
            _logger.LogInformation("[SelfTest] Log file writable: OK ({Path})", _logPath);
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            _logger.LogError(
                "[SelfTest] Log file: FAILED — access denied to {Path}. " +
                "Ensure the service account has write access to the log directory.",
                _logPath);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "[SelfTest] Log file: FAILED — cannot open {Path} for writing", _logPath);
            return false;
        }
    }

    private bool TestDetectionRules()
    {
        var ruleCount = _rules.Count();

        if (ruleCount > 0)
        {
            _logger.LogInformation(
                "[SelfTest] Detection rules loaded: OK ({Count} rules registered)", ruleCount);
            return true;
        }

        _logger.LogError(
            "[SelfTest] Detection rules: FAILED — no rules registered. " +
            "The detection engine will not produce any alerts. " +
            "Check that detection rule classes are properly registered in DI.");
        return false;
    }
}

/// <summary>
/// Result of the startup self-test.
/// </summary>
public sealed class SelfTestResult
{
    public bool EtwAvailable { get; set; }
    public bool DpapiAvailable { get; set; }
    public bool QuarantineWritable { get; set; }
    public bool LogFileWritable { get; set; }
    public bool RulesLoaded { get; set; }

    public bool AllPassed => EtwAvailable && DpapiAvailable &&
                             QuarantineWritable && LogFileWritable && RulesLoaded;

    public int TotalChecks => 5;
    public int PassedCount =>
        (EtwAvailable ? 1 : 0) +
        (DpapiAvailable ? 1 : 0) +
        (QuarantineWritable ? 1 : 0) +
        (LogFileWritable ? 1 : 0) +
        (RulesLoaded ? 1 : 0);
}
