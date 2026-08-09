using System.Collections.Generic;
using System.Linq;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for DllUnloadEngine's sideload detection and OS servicing exclusion logic.
    /// Covers: all sideload targets, boundary values, DISM/NTLite exclusions,
    /// path normalization, and protected process names.
    /// </summary>
    public class DllUnloadEngineTests
    {
        // ═══════════════════════════════════════════════════════════════
        // IsSideloadTargetFileName — positive cases (all known targets)
        // ═══════════════════════════════════════════════════════════════

        [Theory]
        [InlineData("version.dll")]
        [InlineData("dbghelp.dll")]
        [InlineData("winmm.dll")]
        [InlineData("dwrite.dll")]
        [InlineData("cryptsp.dll")]
        [InlineData("userenv.dll")]
        [InlineData("profapi.dll")]
        [InlineData("wtsapi32.dll")]
        [InlineData("dhcpcsvc.dll")]
        [InlineData("iphlpapi.dll")]
        [InlineData("msasn1.dll")]
        [InlineData("netapi32.dll")]
        [InlineData("samcli.dll")]
        [InlineData("sspicli.dll")]
        [InlineData("crypt32.dll")]
        [InlineData("textshaping.dll")]
        [InlineData("winhttp.dll")]
        [InlineData("urlmon.dll")]
        [InlineData("propsys.dll")]
        [InlineData("dwmapi.dll")]
        public void IsSideloadTargetFileName_ReturnsTrue_ForAllKnownTargets(string fileName)
        {
            Assert.True(DllUnloadEngine.IsSideloadTargetFileName(fileName));
        }

        // ── Full path extraction (Path.GetFileName is used internally) ──

        [Theory]
        [InlineData(@"C:\evil\version.dll")]
        [InlineData(@"C:\Users\Attacker\AppData\Local\Temp\dbghelp.dll")]
        [InlineData(@"\\network\share\winmm.dll")]
        [InlineData(@"D:\Program Files\App\cryptsp.dll")]
        public void IsSideloadTargetFileName_ExtractsFileName_FromFullPath(string fullPath)
        {
            Assert.True(DllUnloadEngine.IsSideloadTargetFileName(fullPath));
        }

        // ── Case insensitivity ──────────────────────────────────────────

        [Theory]
        [InlineData("VERSION.DLL")]
        [InlineData("Version.Dll")]
        [InlineData("DBGHELP.DLL")]
        [InlineData("WinMM.DLL")]
        public void IsSideloadTargetFileName_IsCaseInsensitive(string fileName)
        {
            Assert.True(DllUnloadEngine.IsSideloadTargetFileName(fileName));
        }

        // ═══════════════════════════════════════════════════════════════
        // IsSideloadTargetFileName — negative cases
        // ═══════════════════════════════════════════════════════════════

        [Theory]
        [InlineData("DismCorePS.dll")]
        [InlineData("dismprov.dll")]
        [InlineData("OSProvider.dll")]
        [InlineData("dismhost.exe")]
        [InlineData("DismApi.dll")]
        public void IsSideloadTargetFileName_ReturnsFalse_ForDismServicingModules(string fileName)
        {
            Assert.False(DllUnloadEngine.IsSideloadTargetFileName(fileName));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void IsSideloadTargetFileName_ReturnsFalse_ForNullOrEmpty(string? pathOrName)
        {
            Assert.False(DllUnloadEngine.IsSideloadTargetFileName(pathOrName));
        }

        [Theory]
        [InlineData("kernel32.dll")]
        [InlineData("ntdll.dll")]
        [InlineData("user32.dll")]
        [InlineData("gdi32.dll")]
        [InlineData("advapi32.dll")]
        [InlineData("shell32.dll")]
        [InlineData("ole32.dll")]
        [InlineData("msvcrt.dll")]
        [InlineData("myapp.dll")]
        [InlineData("custom_plugin.dll")]
        public void IsSideloadTargetFileName_ReturnsFalse_ForNonTargetDlls(string fileName)
        {
            Assert.False(DllUnloadEngine.IsSideloadTargetFileName(fileName));
        }

        [Theory]
        [InlineData("version.exe")]
        [InlineData("dbghelp.sys")]
        [InlineData("winmm.txt")]
        [InlineData("version")]
        public void IsSideloadTargetFileName_ReturnsFalse_ForWrongExtensions(string fileName)
        {
            Assert.False(DllUnloadEngine.IsSideloadTargetFileName(fileName));
        }

        // ═══════════════════════════════════════════════════════════════
        // SideloadTargets collection — completeness
        // ═══════════════════════════════════════════════════════════════

        [Fact]
        public void SideloadTargets_HasExpectedCount()
        {
            // 20 known sideload target DLLs as of v2.0.3
            Assert.Equal(20, DllUnloadEngine.SideloadTargets.Count);
        }

        [Fact]
        public void SideloadTargets_AllEndWithDll()
        {
            foreach (var target in DllUnloadEngine.SideloadTargets)
            {
                Assert.EndsWith(".dll", target, System.StringComparison.OrdinalIgnoreCase);
            }
        }

        [Fact]
        public void SideloadTargets_NoDuplicates()
        {
            var lower = DllUnloadEngine.SideloadTargets.Select(t => t.ToLowerInvariant()).ToList();
            Assert.Equal(lower.Count, lower.Distinct().Count());
        }

        // ═══════════════════════════════════════════════════════════════
        // Boundary values for IsSideloadTargetFileName
        // ═══════════════════════════════════════════════════════════════

        [Fact]
        public void IsSideloadTargetFileName_DirectoryOnly_ReturnsFalse()
        {
            // Path with no file name component
            Assert.False(DllUnloadEngine.IsSideloadTargetFileName(@"C:\Windows\System32\"));
        }

        [Fact]
        public void IsSideloadTargetFileName_PartialMatch_ReturnsFalse()
        {
            // "version" without .dll extension
            Assert.False(DllUnloadEngine.IsSideloadTargetFileName("version"));
            // "my_version.dll" is not an exact sideload target
            Assert.False(DllUnloadEngine.IsSideloadTargetFileName("my_version.dll"));
        }

        [Fact]
        public void IsSideloadTargetFileName_PathTraversalAttack_StillExtractsCorrectFileName()
        {
            // Path traversal in directory portion — file name should still resolve correctly
            Assert.True(DllUnloadEngine.IsSideloadTargetFileName(@"C:\app\..\temp\version.dll"));
        }

        // ═══════════════════════════════════════════════════════════════
        // DllUnloadResult model
        // ═══════════════════════════════════════════════════════════════

        [Fact]
        public void DllUnloadResult_DefaultValues_AreEmpty()
        {
            var result = new DllUnloadResult();
            Assert.Equal(0, result.ProcessId);
            Assert.Equal("", result.ProcessName);
            Assert.False(result.Success);
            Assert.Empty(result.UnloadedDlls);
        }

        [Fact]
        public void DllUnloadResult_TracksUnloadedDlls()
        {
            var result = new DllUnloadResult
            {
                ProcessId = 1234,
                ProcessName = "target.exe",
                Success = true
            };
            result.UnloadedDlls.Add("version.dll");
            result.UnloadedDlls.Add("dbghelp.dll");

            Assert.Equal(2, result.UnloadedDlls.Count);
            Assert.Contains("version.dll", result.UnloadedDlls);
        }
    }
}
