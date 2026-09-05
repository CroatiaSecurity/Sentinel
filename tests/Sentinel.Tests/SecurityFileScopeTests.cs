using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class SecurityFileScopeTests
    {
        [Theory]
        [InlineData(@"C:\Users\Admin\Downloads\payload.exe", true)]
        [InlineData(@"C:\Windows\Temp\evil.dll", true)]
        [InlineData(@"C:\Windows\System32\drivers\bad.sys", true)]
        [InlineData(@"C:\Users\Admin\Desktop\run.ps1", true)]
        [InlineData(@"C:\Users\Admin\Desktop\note.lnk", true)]
        [InlineData(@"D:\setup.msi", true)]
        [InlineData(@"C:\Users\Admin\AppData\Local\Temp\drop.js", true)]
        [InlineData(@"C:\Users\Admin\AppData\Local\Temp\cache.tmp", false)]
        [InlineData(@"C:\Users\Admin\AppData\Local\Google\Chrome\User Data\Cache\f_0001", false)]
        [InlineData(@"C:\Users\Admin\Pictures\photo.jpg", false)]
        [InlineData(@"C:\Users\Admin\Documents\file.docx", false)]
        [InlineData("payload.exe", false)]
        [InlineData("", false)]
        [InlineData(null, false)]
        public void IsEtwFileEventRelevant_FiltersFirehose(string? path, bool expected)
        {
            Assert.Equal(expected, SecurityFileScope.IsEtwFileEventRelevant(path));
        }

        [Fact]
        public void IsEtwFileEventRelevant_RejectsOverlongPath()
        {
            var path = @"C:\a\" + new string('b', 600) + ".exe";
            Assert.False(SecurityFileScope.IsEtwFileEventRelevant(path));
        }
    }

    public class WorkingSetGuardTests
    {
        [Fact]
        public void ApplyEarly_DoesNotThrow()
        {
            WorkingSetGuard.ApplyEarly();
            WorkingSetGuard.Refresh();
        }

        [Fact]
        public void PinMinimumWorkingSet_DoesNotThrow()
        {
            WorkingSetGuard.PinMinimumWorkingSet();
        }
    }
}
