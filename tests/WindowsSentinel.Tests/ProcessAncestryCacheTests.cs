using System;
using System.Reflection;
using Xunit;
using WindowsSentinel.Core;

namespace WindowsSentinel.Tests
{
    public class ProcessAncestryCacheTests
    {
        [Fact]
        public void ProcessAncestryCache_PreservesEtwParentPidAcrossRefreshes()
        {
            // Arrange
            var cache = new ProcessAncestryCache();
            int myPid = Environment.ProcessId;
            int fakeParentPid = 1337;
            string myName = System.Diagnostics.Process.GetCurrentProcess().ProcessName;

            // Record a high-fidelity ETW-sourced process start (with custom fake parent ID)
            cache.RecordProcessStart(myPid, fakeParentPid, myName, "C:\\mock\\path.exe");

            // Verify it was written to the cache
            var beforeRefresh = cache.GetParent(myPid);
            Assert.Equal(fakeParentPid, beforeRefresh.parentId);
            Assert.Equal(myName, beforeRefresh.name);

            // Act: Invoke the private RefreshCache method via reflection
            var refreshMethod = typeof(ProcessAncestryCache).GetMethod(
                "RefreshCache", BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(refreshMethod);
            refreshMethod!.Invoke(cache, null);

            // Assert: Verify that the custom parent PID was PRESERVED and not overwritten
            // by the NtQueryInformationProcess parent PID retrieved during refresh!
            var afterRefresh = cache.GetParent(myPid);
            Assert.Equal(fakeParentPid, afterRefresh.parentId);
            Assert.Equal(myName, afterRefresh.name);
        }

        [Fact]
        public void ProcessAncestryCache_PrunesExitedProcesses()
        {
            // Arrange
            var cache = new ProcessAncestryCache();
            int fakePid = 999999; // Non-existent PID
            int fakeParent = 1111;

            cache.RecordProcessStart(fakePid, fakeParent, "ghost", "C:\\temp\\ghost.exe");

            // Verify before refresh
            var before = cache.GetParent(fakePid);
            Assert.Equal(fakeParent, before.parentId);

            // Act: Refresh cache (this will see that PID 999999 is not running and prune it)
            var refreshMethod = typeof(ProcessAncestryCache).GetMethod(
                "RefreshCache", BindingFlags.NonPublic | BindingFlags.Instance);
            refreshMethod!.Invoke(cache, null);

            // Assert: It should have been pruned and return unknown/0
            var after = cache.GetParent(fakePid);
            Assert.Equal(0, after.parentId);
            Assert.Equal("unknown", after.name);
        }
    }
}
