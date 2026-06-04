using System;
using System.Collections.Generic;
using Xunit;
using WindowsSentinel.Core;

namespace WindowsSentinel.Tests
{
    public class RulesTests
    {
        private static FusedTelemetryContext MakeProcessContext(string processName, int pid,
            string commandLine = "", string imagePath = "")
        {
            return new FusedTelemetryContext
            {
                ProcessId = pid,
                ProcessName = processName,
                TriggeringEvent = new ProcessTelemetry
                {
                    ProcessName = processName,
                    ProcessId = pid,
                    CommandLine = commandLine,
                    ImagePath = imagePath
                }
            };
        }

        private static FusedTelemetryContext MakeFileContext(string processName, int pid,
            string filePath, string operationType, string? targetPath = null)
        {
            return new FusedTelemetryContext
            {
                ProcessId = pid,
                ProcessName = processName,
                TriggeringEvent = new FileActivityTelemetry
                {
                    ProcessName = processName,
                    ProcessId = pid,
                    FilePath = filePath,
                    OperationType = operationType,
                    TargetPath = targetPath
                }
            };
        }

        // ═══════════════════════════════════════════════════════════════════
        // LsassAccessRule (6 tests)
        // ═══════════════════════════════════════════════════════════════════

        [Fact]
        public void LsassAccessRule_Fires_OnProcdumpLsass()
        {
            var rule = new LsassAccessRule();
            var ctx = MakeProcessContext("procdump.exe", 1234,
                commandLine: "procdump.exe -ma lsass.exe dump.dmp");
            var result = rule.Evaluate(ctx);
            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
            Assert.True(result.KillAuthorized);
        }

        [Fact]
        public void LsassAccessRule_Fires_OnMinidumpLsass()
        {
            var rule = new LsassAccessRule();
            var ctx = MakeProcessContext("dumper.exe", 2345,
                commandLine: "dumper.exe lsass minidump output.bin");
            var result = rule.Evaluate(ctx);
            Assert.NotNull(result);
            Assert.True(result!.Confidence >= 0.90);
        }

        [Fact]
        public void LsassAccessRule_Fires_OnDumptoolLsass()
        {
            var rule = new LsassAccessRule();
            var ctx = MakeProcessContext("evil.exe", 3456,
                commandLine: "evil.exe --target lsass --mode dumptool");
            Assert.NotNull(rule.Evaluate(ctx));
        }

        [Fact]
        public void LsassAccessRule_DoesNotFire_OnUnrelatedCommand()
        {
            var rule = new LsassAccessRule();
            var ctx = MakeProcessContext("notepad.exe", 4567,
                commandLine: "notepad.exe C:\\readme.txt");
            Assert.Null(rule.Evaluate(ctx));
        }

        [Fact]
        public void LsassAccessRule_DoesNotFire_OnLsassAloneWithoutDump()
        {
            var rule = new LsassAccessRule();
            var ctx = MakeProcessContext("svchost.exe", 5678,
                commandLine: "svchost.exe -k lsass");
            Assert.Null(rule.Evaluate(ctx));
        }

        [Fact]
        public void LsassAccessRule_IgnoresNetworkTelemetry()
        {
            var rule = new LsassAccessRule();
            var ctx = new FusedTelemetryContext
            {
                ProcessId = 1000,
                ProcessName = "test",
                TriggeringEvent = new NetworkTelemetry { ProcessName = "test", ProcessId = 1000 }
            };
            Assert.Null(rule.Evaluate(ctx));
        }

        // ═══════════════════════════════════════════════════════════════════
        // RansomwareDetectionRule (8 tests)
        // ═══════════════════════════════════════════════════════════════════

        [Fact]
        public void RansomwareRule_Fires_OnVssadminDeleteShadows()
        {
            var rule = new RansomwareDetectionRule();
            var ctx = MakeProcessContext("cmd.exe", 1000,
                commandLine: "vssadmin.exe delete shadows /all /quiet");
            var result = rule.Evaluate(ctx);
            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
            Assert.True(result.Confidence >= 0.95);
            Assert.True(result.KillAuthorized);
        }

        [Fact]
        public void RansomwareRule_Fires_OnFileRenameToLocked()
        {
            var rule = new RansomwareDetectionRule();
            var ctx = MakeFileContext("malware.exe", 2000,
                "C:\\Users\\doc.docx", "RENAME", "C:\\Users\\doc.docx.locked");
            Assert.NotNull(rule.Evaluate(ctx));
        }

        [Fact]
        public void RansomwareRule_Fires_OnFileRenameToEnc()
        {
            var rule = new RansomwareDetectionRule();
            var ctx = MakeFileContext("cryptor.exe", 3000,
                "C:\\Users\\photo.jpg", "RENAME", "C:\\Users\\photo.jpg.enc");
            Assert.NotNull(rule.Evaluate(ctx));
        }

        [Fact]
        public void RansomwareRule_Fires_OnFileRenameToCrypto()
        {
            var rule = new RansomwareDetectionRule();
            var ctx = MakeFileContext("locker.exe", 4000,
                "C:\\data\\file.txt", "RENAME", "C:\\data\\file.txt.crypto");
            Assert.NotNull(rule.Evaluate(ctx));
        }

        [Fact]
        public void RansomwareRule_DoesNotFire_OnNormalRename()
        {
            var rule = new RansomwareDetectionRule();
            var ctx = MakeFileContext("explorer.exe", 5000,
                "C:\\Users\\doc.docx", "RENAME", "C:\\Users\\doc_old.docx");
            Assert.Null(rule.Evaluate(ctx));
        }

        [Fact]
        public void RansomwareRule_DoesNotFire_OnWriteOperation()
        {
            var rule = new RansomwareDetectionRule();
            var ctx = MakeFileContext("notepad.exe", 6000,
                "C:\\Users\\file.txt", "WRITE");
            Assert.Null(rule.Evaluate(ctx));
        }

        [Fact]
        public void RansomwareRule_DoesNotFire_OnVssadminListShadows()
        {
            var rule = new RansomwareDetectionRule();
            var ctx = MakeProcessContext("cmd.exe", 7000,
                commandLine: "vssadmin.exe list shadows");
            Assert.Null(rule.Evaluate(ctx));
        }

        [Fact]
        public void RansomwareRule_CaseInsensitive()
        {
            var rule = new RansomwareDetectionRule();
            var ctx = MakeProcessContext("CMD.EXE", 8000,
                commandLine: "VSSADMIN DELETE SHADOWS /all");
            Assert.NotNull(rule.Evaluate(ctx));
        }

        // ═══════════════════════════════════════════════════════════════════
        // ReverseShellRule (5 tests)
        // ═══════════════════════════════════════════════════════════════════

        [Fact]
        public void ReverseShellRule_Fires_OnEncodedPowerShell()
        {
            var rule = new ReverseShellRule();
            var ctx = MakeProcessContext("powershell.exe", 1000,
                commandLine: "powershell.exe -enc JABjAGwAaQBlAG4AdAA=");
            var result = rule.Evaluate(ctx);
            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
            Assert.True(result.KillAuthorized);
        }

        [Fact]
        public void ReverseShellRule_Fires_OnEncodedCommand()
        {
            var rule = new ReverseShellRule();
            var ctx = MakeProcessContext("PowerShell.EXE", 2000,
                commandLine: "PowerShell.EXE -EncodedCommand SQBFAFgA");
            Assert.NotNull(rule.Evaluate(ctx));
        }

        [Fact]
        public void ReverseShellRule_DoesNotFire_OnNormalPowerShell()
        {
            var rule = new ReverseShellRule();
            var ctx = MakeProcessContext("powershell.exe", 3000,
                commandLine: "powershell.exe -Command Get-Process");
            Assert.Null(rule.Evaluate(ctx));
        }

        [Fact]
        public void ReverseShellRule_DoesNotFire_OnNonPowerShell()
        {
            var rule = new ReverseShellRule();
            var ctx = MakeProcessContext("cmd.exe", 4000,
                commandLine: "cmd.exe /c echo -enc test");
            Assert.Null(rule.Evaluate(ctx));
        }

        [Fact]
        public void ReverseShellRule_IgnoresNetworkTelemetry()
        {
            var rule = new ReverseShellRule();
            var ctx = new FusedTelemetryContext
            {
                ProcessId = 5000,
                ProcessName = "powershell.exe",
                TriggeringEvent = new NetworkTelemetry { ProcessName = "powershell.exe", ProcessId = 5000 }
            };
            Assert.Null(rule.Evaluate(ctx));
        }

        // ═══════════════════════════════════════════════════════════════════
        // UnsignedBinaryRule (10 tests)
        // ═══════════════════════════════════════════════════════════════════

        [Fact]
        public void UnsignedBinaryRule_Fires_OnTempPath()
        {
            var rule = new UnsignedBinaryRule();
            var ctx = MakeProcessContext("malware.exe", 1000,
                imagePath: @"C:\Users\Admin\AppData\Local\Temp\malware.exe");
            var result = rule.Evaluate(ctx);
            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
            Assert.Equal(0.60, result.Confidence);
        }

        [Fact]
        public void UnsignedBinaryRule_Fires_OnDownloadsPath()
        {
            var rule = new UnsignedBinaryRule();
            var ctx = MakeProcessContext("setup.exe", 2000,
                imagePath: @"C:\Users\Admin\Downloads\setup.exe");
            Assert.NotNull(rule.Evaluate(ctx));
        }

        [Fact]
        public void UnsignedBinaryRule_Fires_OnSuspiciousAppDataPath()
        {
            var rule = new UnsignedBinaryRule();
            var ctx = MakeProcessContext("backdoor.exe", 3000,
                imagePath: @"C:\Users\Admin\AppData\Roaming\backdoor.exe");
            Assert.NotNull(rule.Evaluate(ctx));
        }

        [Fact]
        public void UnsignedBinaryRule_DoesNotFire_OnProgramFiles()
        {
            var rule = new UnsignedBinaryRule();
            var ctx = MakeProcessContext("chrome.exe", 4000,
                imagePath: @"C:\Program Files\Google\Chrome\chrome.exe");
            Assert.Null(rule.Evaluate(ctx));
        }

        [Fact]
        public void UnsignedBinaryRule_DoesNotFire_OnSystem32()
        {
            var rule = new UnsignedBinaryRule();
            var ctx = MakeProcessContext("svchost.exe", 5000,
                imagePath: @"C:\Windows\System32\svchost.exe");
            Assert.Null(rule.Evaluate(ctx));
        }

        [Fact]
        public void UnsignedBinaryRule_DoesNotFire_OnTrustedAppDataPrograms()
        {
            var rule = new UnsignedBinaryRule();
            var ctx = MakeProcessContext("Slack.exe", 6000,
                imagePath: @"C:\Users\Admin\AppData\Local\Slack\Slack.exe");
            Assert.Null(rule.Evaluate(ctx));
        }

        [Fact]
        public void UnsignedBinaryRule_DoesNotFire_OnDiscordAppData()
        {
            var rule = new UnsignedBinaryRule();
            var ctx = MakeProcessContext("Discord.exe", 7000,
                imagePath: @"C:\Users\Admin\AppData\Local\Discord\Discord.exe");
            Assert.Null(rule.Evaluate(ctx));
        }

        [Fact]
        public void UnsignedBinaryRule_DoesNotFire_OnLocalPrograms()
        {
            var rule = new UnsignedBinaryRule();
            var ctx = MakeProcessContext("Windsurf.exe", 8000,
                imagePath: @"C:\Users\Admin\AppData\Local\Programs\Windsurf\Windsurf.exe");
            Assert.Null(rule.Evaluate(ctx));
        }

        [Fact]
        public void UnsignedBinaryRule_DoesNotFire_OnNoPathSeparator()
        {
            var rule = new UnsignedBinaryRule();
            var ctx = MakeProcessContext("svchost.exe", 9000, imagePath: "svchost.exe");
            Assert.Null(rule.Evaluate(ctx));
        }

        [Fact]
        public void UnsignedBinaryRule_IsLogOnly()
        {
            var rule = new UnsignedBinaryRule();
            var ctx = MakeProcessContext("payload.exe", 10000,
                imagePath: @"C:\Users\Admin\AppData\Local\Temp\payload.exe");
            var result = rule.Evaluate(ctx);
            Assert.NotNull(result);
            Assert.False(result!.KillAuthorized);
        }

        // ═══════════════════════════════════════════════════════════════════
        // PrivilegeEscalationRule tests
        // ═══════════════════════════════════════════════════════════════════

        [Fact]
        public void PrivilegeEscalationRule_Fires_OnUacBypass()
        {
            var rule = new PrivilegeEscalationRule();
            var ctx = MakeProcessContext("fodhelper.exe", 1001,
                commandLine: "fodhelper.exe",
                imagePath: @"C:\Windows\System32\fodhelper.exe");
            var result = rule.Evaluate(ctx);
            Assert.NotNull(result);
            Assert.Equal("PrivilegeEscalationRule", result!.RuleName);
            Assert.True(result.KillAuthorized);
        }

        [Fact]
        public void PrivilegeEscalationRule_Fires_OnGetSystem()
        {
            var rule = new PrivilegeEscalationRule();
            var ctx = MakeProcessContext("evil.exe", 1002,
                commandLine: "evil.exe -getsystem",
                imagePath: @"C:\Users\Admin\Downloads\evil.exe");
            var result = rule.Evaluate(ctx);
            Assert.NotNull(result);
            Assert.True(result!.Confidence >= 0.85);
        }

        [Fact]
        public void PrivilegeEscalationRule_Fires_OnNamedPipeImpersonation_CmdRedirection()
        {
            var rule = new PrivilegeEscalationRule();
            var ctx = MakeProcessContext("cmd.exe", 1003,
                commandLine: @"cmd.exe /c echo hello > \\.\pipe\test",
                imagePath: @"C:\Windows\System32\cmd.exe");
            var result = rule.Evaluate(ctx);
            Assert.NotNull(result);
            Assert.True(result!.KillAuthorized);
        }

        [Fact]
        public void PrivilegeEscalationRule_DoesNotFire_OnLegitimateLanguageServerPipe()
        {
            var rule = new PrivilegeEscalationRule();
            var ctx = MakeProcessContext("language_server_windows_x64.exe", 1004,
                commandLine: @"c:\Users\Admin\AppData\Local\Programs\Antigravity IDE\resources\app\extensions\antigravity\bin\language_server_windows_x64.exe --enable_lsp --parent_pipe_path \\.\pipe\server_12345",
                imagePath: @"c:\Users\Admin\AppData\Local\Programs\Antigravity IDE\resources\app\extensions\antigravity\bin\language_server_windows_x64.exe");
            var result = rule.Evaluate(ctx);
            Assert.Null(result);
        }

        [Fact]
        public void PrivilegeEscalationRule_DoesNotFire_OnExplorerSpawnedFodhelper()
        {
            var rule = new PrivilegeEscalationRule();
            var ctx = new FusedTelemetryContext
            {
                ProcessId = 1005,
                ProcessName = "fodhelper.exe",
                TriggeringEvent = new ProcessTelemetry
                {
                    ProcessName = "fodhelper.exe",
                    ProcessId = 1005,
                    CommandLine = "fodhelper.exe",
                    ImagePath = @"C:\Windows\System32\fodhelper.exe",
                    ParentProcessName = "explorer"
                }
            };
            var result = rule.Evaluate(ctx);
            Assert.Null(result);
        }
    }
}
