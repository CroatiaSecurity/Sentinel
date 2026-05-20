using WindowsSentinel.Core.Detection.Rules;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;
using Xunit;

namespace WindowsSentinel.Tests.Detection;

/// <summary>
/// Verifies that Tier2 rules are always Tier2 (log only).
/// Per spec: Tier2 must NEVER trigger a response action.
/// </summary>
public sealed class Tier2RulesTests
{
    // ── UnsignedBinaryRule ───────────────────────────────────────────────────

    [Fact]
    public void UnsignedBinaryRule_IsTier2()
    {
        var rule = new UnsignedBinaryRule();
        Assert.Equal(DetectionTier.Tier2Indicator, rule.Tier);
    }

    [Fact]
    public void UnsignedBinaryRule_DoesNotFire_ForSystemPath()
    {
        var rule = new UnsignedBinaryRule();
        var telemetry = MakeProcess("svchost.exe", 1000,
            imagePath: @"C:\Windows\System32\svchost.exe");

        Assert.Null(rule.Evaluate(telemetry));
    }

    [Fact]
    public void UnsignedBinaryRule_DoesNotFire_ForProgramFiles()
    {
        var rule = new UnsignedBinaryRule();
        var telemetry = MakeProcess("app.exe", 1001,
            imagePath: @"C:\Program Files\MyApp\app.exe");

        Assert.Null(rule.Evaluate(telemetry));
    }

    [Fact]
    public void UnsignedBinaryRule_WhenFires_IsTier2()
    {
        var rule = new UnsignedBinaryRule();
        var telemetry = MakeProcess("suspicious.exe", 9999,
            imagePath: @"C:\Users\user\AppData\Local\Temp\suspicious.exe");

        var result = rule.Evaluate(telemetry);

        if (result is not null)
            Assert.Equal(DetectionTier.Tier2Indicator, result.Tier);
    }

    [Fact]
    public void UnsignedBinaryRule_WhenFires_FromStagingPath_HasHigherConfidence()
    {
        var rule = new UnsignedBinaryRule();
        // Non-existent file — will be treated as unsigned
        var stagingTelemetry = MakeProcess("payload.exe", 1111,
            imagePath: @"C:\Users\user\AppData\Local\Temp\payload.exe");
        var normalTelemetry = MakeProcess("payload.exe", 2222,
            imagePath: @"C:\MyApp\payload.exe");

        var stagingResult = rule.Evaluate(stagingTelemetry);
        var normalResult  = rule.Evaluate(normalTelemetry);

        // If both fire, staging path should have higher confidence
        if (stagingResult is not null && normalResult is not null)
            Assert.True(stagingResult.Confidence > normalResult.Confidence);
    }

    // ── HighEntropyRule ──────────────────────────────────────────────────────

    [Fact]
    public void HighEntropyRule_IsTier2()
    {
        var rule = new HighEntropyRule();
        Assert.Equal(DetectionTier.Tier2Indicator, rule.Tier);
    }

    [Fact]
    public void HighEntropyRule_Fires_OnHighEntropyName()
    {
        var rule = new HighEntropyRule();
        var telemetry = MakeProcess("aB3cD4eF5gH6iJ7kL8mN9.exe", 1111);

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
    }

    [Fact]
    public void HighEntropyRule_DoesNotFire_OnLowEntropyName()
    {
        var rule = new HighEntropyRule();
        var telemetry = MakeProcess("notepad.exe", 2222);

        Assert.Null(rule.Evaluate(telemetry));
    }

    [Fact]
    public void HighEntropyRule_DoesNotFire_OnShortName()
    {
        var rule = new HighEntropyRule();
        // Very short names can have high entropy by chance — should be excluded
        var telemetry = MakeProcess("ab.exe", 3333);

        Assert.Null(rule.Evaluate(telemetry));
    }

    [Fact]
    public void HighEntropyRule_DoesNotFire_OnGuidLikeName()
    {
        var rule = new HighEntropyRule();
        // GUID-named temp files are common in legitimate installers
        var telemetry = MakeProcess("{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}.exe", 4444);

        Assert.Null(rule.Evaluate(telemetry));
    }

    // ── SuspiciousImportsRule ────────────────────────────────────────────────

    [Fact]
    public void SuspiciousImportsRule_IsTier2()
    {
        var rule = new SuspiciousImportsRule();
        Assert.Equal(DetectionTier.Tier2Indicator, rule.Tier);
    }

    [Fact]
    public void SuspiciousImportsRule_Fires_OnSuspiciousApiInCommandLine()
    {
        var rule = new SuspiciousImportsRule();
        var telemetry = MakeProcess("loader.exe", 3333,
            commandLine: "loader.exe VirtualAlloc GetProcAddress LoadLibrary");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
    }

    [Fact]
    public void SuspiciousImportsRule_ConfidenceScales_WithMatchCount()
    {
        var rule = new SuspiciousImportsRule();
        var oneMatch = MakeProcess("loader.exe", 1, commandLine: "loader.exe VirtualAlloc");
        var manyMatches = MakeProcess("loader.exe", 2,
            commandLine: "loader.exe VirtualAlloc GetProcAddress LoadLibrary CreateThread OpenProcess");

        var r1 = rule.Evaluate(oneMatch);
        var r2 = rule.Evaluate(manyMatches);

        Assert.NotNull(r1);
        Assert.NotNull(r2);
        Assert.True(r2!.Confidence > r1!.Confidence);
    }

    [Fact]
    public void SuspiciousImportsRule_Fires_OnReconCommand_Whoami()
    {
        var rule = new SuspiciousImportsRule();
        var telemetry = MakeProcess("whoami.exe", 5555,
            commandLine: "whoami.exe /all");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
    }

    [Fact]
    public void SuspiciousImportsRule_Fires_OnReconCommand_NetUserDomain()
    {
        var rule = new SuspiciousImportsRule();
        var telemetry = MakeProcess("net.exe", 6666,
            commandLine: "net.exe user /domain");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
    }

    [Fact]
    public void SuspiciousImportsRule_Fires_OnPersistencePattern_RegRun()
    {
        var rule = new SuspiciousImportsRule();
        var telemetry = MakeProcess("reg.exe", 7777,
            commandLine: @"reg.exe add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Malware /t REG_SZ /d C:\Temp\evil.exe");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
    }

    [Fact]
    public void SuspiciousImportsRule_Fires_OnPersistencePattern_Schtasks()
    {
        var rule = new SuspiciousImportsRule();
        var telemetry = MakeProcess("schtasks.exe", 8888,
            commandLine: "schtasks.exe /create /tn Updater /tr C:\\Temp\\evil.exe /sc onlogon");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
    }

    [Fact]
    public void SuspiciousImportsRule_DoesNotFire_OnCleanCommandLine()
    {
        var rule = new SuspiciousImportsRule();
        var telemetry = MakeProcess("notepad.exe", 4444,
            commandLine: "notepad.exe C:\\readme.txt");

        Assert.Null(rule.Evaluate(telemetry));
    }

    // ── ResponseEngine contract ──────────────────────────────────────────────

    [Fact]
    public async Task ResponseEngine_NeverActsOnTier2_EvenWhenActiveResponseEnabled()
    {
        var mockLogger = Microsoft.Extensions.Logging.Abstractions
            .NullLogger<WindowsSentinel.Core.Engine.AdvancedResponseEngine>.Instance;
        var scoringLogger = Microsoft.Extensions.Logging.Abstractions
            .NullLogger<WindowsSentinel.Core.Engine.ScoringEngine>.Instance;

        var loggedActions = new List<ResponseAction>();
        var mockEventLogger = new InMemoryEventLogger(loggedActions);
        var scoringEngine = new WindowsSentinel.Core.Engine.ScoringEngine(scoringLogger);

        var engine = new WindowsSentinel.Core.Engine.AdvancedResponseEngine(
            mockEventLogger,
            mockLogger,
            scoringEngine,
            activeResponseEnabled: true);

        var tier2Detection = new DetectionEvent
        {
            RuleName    = "Test Tier2 Rule",
            Evidence    = "test evidence",
            Reasoning   = "test reasoning",
            Confidence  = 0.5,
            Tier        = DetectionTier.Tier2Indicator,
            ProcessName = "test.exe",
            ProcessId   = 99999,
            Timestamp   = DateTimeOffset.UtcNow
        };

        await engine.HandleAsync(tier2Detection, CancellationToken.None);

        Assert.Single(loggedActions);
        Assert.Equal(ResponseActionKind.LogOnly, loggedActions[0].Kind);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static ProcessTelemetry MakeProcess(
        string name, int pid,
        string commandLine = "",
        string imagePath   = "")
    {
        return new ProcessTelemetry
        {
            EventType       = "ProcessStart",
            ProcessId       = pid,
            ProcessName     = name,
            ImagePath       = string.IsNullOrEmpty(imagePath) ? $@"C:\Users\user\AppData\{name}" : imagePath,
            CommandLine     = commandLine,
            ParentProcessId = 4,
            Timestamp       = DateTimeOffset.UtcNow
        };
    }
}

/// <summary>In-memory event logger for testing.</summary>
internal sealed class InMemoryEventLogger : WindowsSentinel.Core.Interfaces.IEventLogger
{
    private readonly List<ResponseAction> _actions;

    public InMemoryEventLogger(List<ResponseAction> actions) => _actions = actions;

    public Task LogDetectionAsync(DetectionEvent detection, CancellationToken cancellationToken)
        => Task.CompletedTask;

    public Task LogResponseAsync(ResponseAction action, CancellationToken cancellationToken)
    {
        _actions.Add(action);
        return Task.CompletedTask;
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}


