using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Guards against DllUnloadEngine treating NTLite/DISM modules as sideloads.
    /// </summary>
    public class DllUnloadEngineTests
    {
        [Fact]
        public void SideloadTargets_Does_Not_Include_Dism_Or_Servicing_Modules()
        {
            // Legitimate DISM/NTLite loads — must never be classic sideload targets
            Assert.False(DllUnloadEngine.IsSideloadTargetFileName("DismCorePS.dll"));
            Assert.False(DllUnloadEngine.IsSideloadTargetFileName("dismprov.dll"));
            Assert.False(DllUnloadEngine.IsSideloadTargetFileName("OSProvider.dll"));
            Assert.False(DllUnloadEngine.IsSideloadTargetFileName("dismhost.exe"));
            Assert.False(DllUnloadEngine.IsSideloadTargetFileName("DismApi.dll"));
            // Classic attack plants still covered
            Assert.True(DllUnloadEngine.IsSideloadTargetFileName("version.dll"));
            Assert.True(DllUnloadEngine.IsSideloadTargetFileName("dbghelp.dll"));
            Assert.True(DllUnloadEngine.IsSideloadTargetFileName(@"C:\evil\winmm.dll"));
        }
    }
}
