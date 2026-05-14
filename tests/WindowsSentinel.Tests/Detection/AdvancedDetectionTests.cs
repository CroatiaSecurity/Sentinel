using WindowsSentinel.Core.Detection.Rules;
using WindowsSentinel.Core.Engine;
using WindowsSentinel.Core.Interfaces;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace WindowsSentinel.Tests.Detection;

/// <summary>
/// Tests for the advanced detection components:
///   - ThreatIntelInjectionRule
///   - BeaconingRule
///   - HollowProcessRule
///   - BehavioralCorrelationEngine (composite detections)
///   - ProcessInjectionRule parent-child detection
/// </summary>
public sealed class AdvancedDetectionTests
{
    // ── ThreatIntelInjectionRule ─────────────────────────────────────────────

    [Fact]
    public void ThreatIntelRule_IsTier1()
    {
        var rule = new ThreatIntelInjectionRule();
        Assert.Equal(DetectionTier.Tier1Behavioral, rule.Tier);
    }

    [Fact]
    public void ThreatIntelRule_Fires_OnCrossProcessAllocVm()
    {
        var rule = new ThreatIntelInjectionRule();
        var telemetry = new ThreatIntelTelemetry
        {
            EventKind       = ThreatIntelEventKind.CrossProcessAllocVm,
            CallerProcessId = 1234,
            TargetProcessId = 5678,
            Evidence        = "VirtualAllocEx: PID 1234 allocated memory in PID 5678",
            Confidence      = 0.82,
            Timestamp       = DateTimeOffset.UtcNow,
            RawData         = new Dictionary<string, string>()
        };

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
        Assert.Equal(0.82, result.Confidence);
    }

    [Fact]
    public void ThreatIntelRule_Fires_OnSetThreadContext()
    {
        var rule = new ThreatIntelInjectionRule();
        var telemetry = new ThreatIntelTelemetry
        {
            EventKind       = ThreatIntelEventKind.CrossProcessSetThreadContext,
            CallerProcessId = 1234,
            TargetProcessId = 5678,
            Evidence        = "SetThreadContext: PID 1234 modified thread in PID 5678",
            Confidence      = 0.93,
            Timestamp       = DateTimeOffset.UtcNow,
            RawData         = new Dictionary<string, string>()
        };

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
        Assert.True(result.Confidence >= 0.90);
    }

    [Fact]
    public void ThreatIntelRule_DoesNotFire_OnUnrelatedTelemetry()
    {
        var rule = new ThreatIntelInjectionRule();
        var telemetry = MakeProcess("notepad.exe", 1234);

        Assert.Null(rule.Evaluate(telemetry));
    }

    // ── BeaconingRule ────────────────────────────────────────────────────────

    [Fact]
    public void BeaconingRule_IsTier1()
    {
        var rule = new BeaconingRule();
        Assert.Equal(DetectionTier.Tier1Behavioral, rule.Tier);
    }

    [Fact]
    public void BeaconingRule_Fires_OnLowCvBeacon()
    {
        var rule = new BeaconingRule();
        var telemetry = new BeaconingTelemetry
        {
            ProcessId              = 1234,
            ProcessName            = "suspicious.exe",
            RemoteAddress          = "10.0.0.1",
            RemotePort             = 4444,
            MeanIntervalSec        = 60.0,
            StdDevSec              = 3.0,
            CoefficientOfVariation = 0.05,  // very regular — beacon
            ObservationCount       = 10,
            Timestamp              = DateTimeOffset.UtcNow
        };

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
        Assert.True(result.Confidence > 0.0);
        Assert.Contains("CV=0.050", result.Evidence);
    }

    [Fact]
    public void BeaconingRule_ConfidenceScales_WithObservationCount()
    {
        var rule = new BeaconingRule();

        var fewObs = new BeaconingTelemetry
        {
            ProcessId = 1, ProcessName = "x.exe", RemoteAddress = "1.1.1.1", RemotePort = 4444,
            MeanIntervalSec = 60, StdDevSec = 3, CoefficientOfVariation = 0.05,
            ObservationCount = 5, Timestamp = DateTimeOffset.UtcNow
        };
        var manyObs = new BeaconingTelemetry
        {
            ProcessId = 1, ProcessName = "x.exe", RemoteAddress = "1.1.1.1", RemotePort = 4444,
            MeanIntervalSec = 60, StdDevSec = 3, CoefficientOfVariation = 0.05,
            ObservationCount = 20, Timestamp = DateTimeOffset.UtcNow
        };

        var r1 = rule.Evaluate(fewObs);
        var r2 = rule.Evaluate(manyObs);

        Assert.NotNull(r1);
        Assert.NotNull(r2);
        Assert.True(r2!.Confidence >= r1!.Confidence);
    }

    [Fact]
    public void BeaconingRule_DoesNotFire_OnUnrelatedTelemetry()
    {
        var rule = new BeaconingRule();
        Assert.Null(rule.Evaluate(MakeProcess("notepad.exe", 1)));
    }

    // ── HollowProcessRule ────────────────────────────────────────────────────

    [Fact]
    public void HollowProcessRule_IsTier1()
    {
        var rule = new HollowProcessRule();
        Assert.Equal(DetectionTier.Tier1Behavioral, rule.Tier);
    }

    [Fact]
    public void HollowProcessRule_Fires_OnHollowedProcess()
    {
        var rule = new HollowProcessRule();
        var telemetry = new HollowProcessTelemetry
        {
            ProcessId    = 1234,
            ProcessName  = "svchost.exe",
            DeclaredPath = @"C:\Windows\System32\svchost.exe",
            HollowType   = "HOLLOWED",
            Evidence     = "Declared: svchost.exe | Actual: C:\\Temp\\evil.exe",
            Confidence   = 0.92,
            Timestamp    = DateTimeOffset.UtcNow
        };

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
        Assert.True(result.Confidence >= 0.90);
        Assert.Contains("hollowing", result.Reasoning, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void HollowProcessRule_Fires_OnUnmappedBase()
    {
        var rule = new HollowProcessRule();
        var telemetry = new HollowProcessTelemetry
        {
            ProcessId    = 5678,
            ProcessName  = "loader.exe",
            DeclaredPath = @"C:\Temp\loader.exe",
            HollowType   = "UNMAPPED_BASE",
            Evidence     = "No mapped file at base address",
            Confidence   = 0.75,
            Timestamp    = DateTimeOffset.UtcNow
        };

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
        Assert.Contains("shellcode", result.Reasoning, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void HollowProcessRule_DoesNotFire_OnUnrelatedTelemetry()
    {
        var rule = new HollowProcessRule();
        Assert.Null(rule.Evaluate(MakeProcess("notepad.exe", 1)));
    }

    // ── ProcessInjectionRule — parent-child detection ────────────────────────

    [Fact]
    public void ProcessInjectionRule_Fires_OnWordSpawningPowerShell()
    {
        var rule = new ProcessInjectionRule();
        var telemetry = new ProcessTelemetry
        {
            EventType         = "ProcessStart",
            ProcessId         = 9999,
            ProcessName       = "powershell.exe",
            ImagePath         = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            CommandLine       = "powershell.exe -nop -w hidden",
            ParentProcessId   = 1111,
            ParentProcessName = "winword.exe",
            Timestamp         = DateTimeOffset.UtcNow
        };

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
        Assert.Contains("winword.exe", result.Evidence);
    }

    [Fact]
    public void ProcessInjectionRule_Fires_OnExcelSpawningCmd()
    {
        var rule = new ProcessInjectionRule();
        var telemetry = new ProcessTelemetry
        {
            EventType         = "ProcessStart",
            ProcessId         = 8888,
            ProcessName       = "cmd.exe",
            ImagePath         = @"C:\Windows\System32\cmd.exe",
            CommandLine       = "cmd.exe /c whoami",
            ParentProcessId   = 2222,
            ParentProcessName = "excel.exe",
            Timestamp         = DateTimeOffset.UtcNow
        };

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
    }

    [Fact]
    public void ProcessInjectionRule_DoesNotFire_OnExplorerSpawningNotepad()
    {
        var rule = new ProcessInjectionRule();
        var telemetry = new ProcessTelemetry
        {
            EventType         = "ProcessStart",
            ProcessId         = 7777,
            ProcessName       = "notepad.exe",
            ImagePath         = @"C:\Windows\System32\notepad.exe",
            CommandLine       = "notepad.exe",
            ParentProcessId   = 3333,
            ParentProcessName = "explorer.exe",
            Timestamp         = DateTimeOffset.UtcNow
        };

        Assert.Null(rule.Evaluate(telemetry));
    }

    // ── BehavioralCorrelationEngine ──────────────────────────────────────────

    [Fact]
    public async Task CorrelationEngine_Fires_OnRansomwareChain()
    {
        var emitted = new List<DetectionEvent>();
        var mockEngine = new CapturingDetectionEngine(emitted);
        var engine = new BehavioralCorrelationEngine(
            mockEngine,
            NullLogger<BehavioralCorrelationEngine>.Instance);

        // Signal 1: shadow copy deletion (process signal)
        var shadowSignal = new DetectionEvent
        {
            RuleName    = "Ransomware-Like Activity",
            Evidence    = "vssadmin delete shadows",
            Reasoning   = "test",
            Confidence  = 0.96,
            Tier        = DetectionTier.Tier1Behavioral,
            ProcessName = "vssadmin.exe",
            ProcessId   = 1111,
            Timestamp   = DateTimeOffset.UtcNow,
            Metadata    = new() { ["MatchedPattern"] = "delete shadows" }
        };

        // Signal 2: bulk file rename (file signal)
        var renameSignal = new DetectionEvent
        {
            RuleName    = "Ransomware-Like Activity",
            Evidence    = "bulk rename",
            Reasoning   = "test",
            Confidence  = 0.82,
            Tier        = DetectionTier.Tier1Behavioral,
            ProcessName = "FileSystem",
            ProcessId   = 0,
            Timestamp   = DateTimeOffset.UtcNow,
            Metadata    = new() { ["RenameCount"] = "25", ["NewPath"] = @"C:\file.locked" }
        };

        await engine.OnDetectionAsync(shadowSignal, CancellationToken.None);
        await engine.OnDetectionAsync(renameSignal, CancellationToken.None);

        // Should have fired a composite detection
        var composite = emitted.FirstOrDefault(e => e.RuleName.Contains("COMPOSITE"));
        Assert.NotNull(composite);
        Assert.Equal(DetectionTier.Tier1Behavioral, composite!.Tier);
        Assert.True(composite.Confidence >= 0.95);
    }

    [Fact]
    public async Task CorrelationEngine_Fires_OnPostExploitRecon()
    {
        var emitted = new List<DetectionEvent>();
        var mockEngine = new CapturingDetectionEngine(emitted);
        var engine = new BehavioralCorrelationEngine(
            mockEngine,
            NullLogger<BehavioralCorrelationEngine>.Instance);

        // Three distinct recon commands
        var reconTypes = new[] { "Full user/group/privilege enumeration", "Domain user enumeration", "Full network configuration dump" };
        foreach (var reconType in reconTypes)
        {
            var signal = new DetectionEvent
            {
                RuleName    = "Suspicious API / Recon Pattern",
                Evidence    = $"recon: {reconType}",
                Reasoning   = "test",
                Confidence  = 0.40,
                Tier        = DetectionTier.Tier2Indicator,
                ProcessName = "cmd.exe",
                ProcessId   = 1234,
                Timestamp   = DateTimeOffset.UtcNow,
                Metadata    = new() { ["ReconType"] = reconType }
            };
            await engine.OnDetectionAsync(signal, CancellationToken.None);
        }

        var composite = emitted.FirstOrDefault(e => e.RuleName.Contains("Recon") && e.RuleName.Contains("COMPOSITE"));
        Assert.NotNull(composite);
        Assert.Equal(DetectionTier.Tier1Behavioral, composite!.Tier);
    }

    [Fact]
    public async Task CorrelationEngine_DoesNotFireComposite_ForSingleSignal()
    {
        var emitted = new List<DetectionEvent>();
        var mockEngine = new CapturingDetectionEngine(emitted);
        var engine = new BehavioralCorrelationEngine(
            mockEngine,
            NullLogger<BehavioralCorrelationEngine>.Instance);

        var signal = new DetectionEvent
        {
            RuleName    = "Ransomware-Like Activity",
            Evidence    = "single signal",
            Reasoning   = "test",
            Confidence  = 0.82,
            Tier        = DetectionTier.Tier1Behavioral,
            ProcessName = "vssadmin.exe",
            ProcessId   = 1111,
            Timestamp   = DateTimeOffset.UtcNow,
            Metadata    = new() { ["MatchedPattern"] = "delete shadows" }
        };

        await engine.OnDetectionAsync(signal, CancellationToken.None);

        Assert.Empty(emitted); // No composite from a single signal
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static ProcessTelemetry MakeProcess(string name, int pid) =>
        new()
        {
            EventType         = "ProcessStart",
            ProcessId         = pid,
            ProcessName       = name,
            ImagePath         = $@"C:\Windows\{name}",
            CommandLine       = name,
            ParentProcessId   = 4,
            ParentProcessName = string.Empty,
            Timestamp         = DateTimeOffset.UtcNow
        };
}

/// <summary>
/// Test double for IDetectionEngine that captures EmitAsync calls.
/// </summary>
internal sealed class CapturingDetectionEngine : IDetectionEngine
{
    private readonly List<DetectionEvent> _captured;

    public CapturingDetectionEngine(List<DetectionEvent> captured)
        => _captured = captured;

    public IAsyncEnumerable<DetectionEvent> DetectionStream =>
        throw new NotImplementedException();

    public Task ProcessAsync(object telemetry, CancellationToken cancellationToken)
        => Task.CompletedTask;

    public Task EmitAsync(DetectionEvent detection, CancellationToken cancellationToken)
    {
        _captured.Add(detection);
        return Task.CompletedTask;
    }
}
