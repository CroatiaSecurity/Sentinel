using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class NativeResolverCompletenessTests
    {
        private static readonly HashSet<string> InspectionApis = new(StringComparer.Ordinal)
        {
            "OpenProcess",
            "ReadProcessMemory",
            "VirtualQueryEx",
            "DuplicateHandle",
            "NtQuerySystemInformation",
            "NtQueryObject",
            "NtQueryInformationProcess",
        };

        [Fact]
        public void InspectionApis_HaveNoStaticDllImport_OutsideNativeResolver()
        {
            var leftovers = new List<string>();
            var asm = typeof(NativeResolver).Assembly;
            foreach (var type in asm.GetTypes())
            {
                if (type == typeof(NativeResolver))
                    continue;

                foreach (var method in type.GetMethods(
                    BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
                {
                    var dll = method.GetCustomAttribute<DllImportAttribute>();
                    if (dll == null)
                        continue;
                    var entry = string.IsNullOrEmpty(dll.EntryPoint) ? method.Name : dll.EntryPoint;
                    if (InspectionApis.Contains(entry))
                        leftovers.Add($"{type.FullName}.{method.Name} -> {dll.Value}!{entry}");
                }
            }

            Assert.True(leftovers.Count == 0,
                "Static DllImport of inspection APIs remains outside NativeResolver:\n" +
                string.Join("\n", leftovers));
        }

        [Fact]
        public void OpenProcess_ResolvesAtRuntime_ForCurrentProcess()
        {
            int pid = Process.GetCurrentProcess().Id;
            IntPtr h = NativeResolver.OpenProcess(
                NativeProcessMemory.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            Assert.NotEqual(IntPtr.Zero, h);
            Assert.True(NativeProcessMemory.CloseHandle(h));
        }

        [Fact]
        public void NativeResolver_ExposesAllSevenInspectionForwards()
        {
            var names = typeof(NativeResolver)
                .GetMethods(BindingFlags.Public | BindingFlags.Static)
                .Select(m => m.Name)
                .ToHashSet(StringComparer.Ordinal);
            foreach (var api in InspectionApis)
                Assert.Contains(api, names);
        }
    }
}
