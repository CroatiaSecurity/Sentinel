using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// Elevated first-run / upgrade helpers invoked as
    /// <c>Sentinel.Service.exe --install</c> / <c>--prepare-upgrade</c>.
    /// Keeps SCM create, Run-key, and stop/start out of the Inno Setup script so the
    /// setup EXE does not embed classic "sc create + Run + taskkill + icacls" AV bait.
    /// </summary>
    public static class InstallBootstrap
    {
        public const string ServiceName = "Sentinel";
        public const string AgentRunValueName = "SentinelAgent";

        private const uint ScManagerAllAccess = 0xF003F;
        private const uint ServiceAllAccess = 0xF01FF;
        private const uint ServiceQueryStatus = 0x0004;
        private const uint ServiceStart = 0x0010;
        private const uint ServiceStop = 0x0020;
        private const uint ServiceWin32OwnProcess = 0x10;
        private const uint ServiceAutoStart = 0x02;
        private const uint ServiceErrorNormal = 0x01;
        private const uint ServiceNoChange = 0xFFFFFFFF;
        private const uint ServiceControlStop = 0x00000001;
        private const int ErrorServiceExists = 1073;
        private const int ErrorServiceDoesNotExist = 1060;
        private const int ErrorServiceMarkedForDelete = 1072;

        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "CreateServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateService(IntPtr hSCManager, string lpServiceName, string lpDisplayName,
            uint dwDesiredAccess, uint dwServiceType, uint dwStartType, uint dwErrorControl,
            string lpBinaryPathName, string? lpLoadOrderGroup, IntPtr lpdwTagId,
            string? lpDependencies, string? lpServiceStartName, string? lpPassword);

        [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfigW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ChangeServiceConfig(IntPtr hService, uint dwServiceType, uint dwStartType,
            uint dwErrorControl, string? lpBinaryPathName, string? lpLoadOrderGroup, IntPtr lpdwTagId,
            string? lpDependencies, string? lpServiceStartName, string? lpPassword, string? lpDisplayName);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool StartService(IntPtr hService, int dwNumServiceArgs, IntPtr lpServiceArgVectors);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ControlService(IntPtr hService, uint dwControl, ref SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool QueryServiceStatus(IntPtr hService, ref SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);

        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_STATUS
        {
            public uint dwServiceType;
            public uint dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
        }

        /// <summary>
        /// Idempotent post-copy install: ensure SCM service, Run key, SafeBoot, start service, launch agent.
        /// </summary>
        public static int RunInstall(string? installDir = null)
        {
            try
            {
                installDir ??= Path.GetDirectoryName(Process.GetCurrentProcess().MainModule?.FileName
                    ?? AppContext.BaseDirectory)
                    ?? AppContext.BaseDirectory;

                var serviceExe = Path.Combine(installDir, "Sentinel.Service.exe");
                var agentExe = Path.Combine(installDir, "Sentinel.Agent.exe");
                if (!File.Exists(serviceExe))
                    return 2;

                EnsureService(serviceExe);
                EnsureAgentRunKey(agentExe);
                HardeningModule.RegisterForSafeModePublic();
                TryStartService();
                TryLaunchAgent(agentExe);
                return 0;
            }
            catch
            {
                return 1;
            }
        }

        /// <summary>
        /// Stop the running service cleanly so Setup can overwrite binaries (no taskkill / icacls).
        /// </summary>
        public static int RunPrepareUpgrade()
        {
            try
            {
                TryStopService(waitMs: 8000);
                return 0;
            }
            catch
            {
                return 1;
            }
        }

        public static void EnsureService(string serviceExePath)
        {
            var full = Path.GetFullPath(serviceExePath);
            var quoted = full.Contains(" ") ? $"\"{full}\"" : full;

            var scm = OpenSCManager(null, null, ScManagerAllAccess);
            if (scm == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            try
            {
                var svc = OpenService(scm, ServiceName, ServiceAllAccess);
                if (svc == IntPtr.Zero)
                {
                    var err = Marshal.GetLastWin32Error();
                    if (err != ErrorServiceDoesNotExist)
                        throw new Win32Exception(err);

                    svc = CreateService(
                        scm, ServiceName, "Sentinel",
                        ServiceAllAccess, ServiceWin32OwnProcess, ServiceAutoStart, ServiceErrorNormal,
                        quoted, null, IntPtr.Zero, null, null, null);
                    if (svc == IntPtr.Zero)
                    {
                        var createErr = Marshal.GetLastWin32Error();
                        if (createErr != ErrorServiceExists)
                            throw new Win32Exception(createErr);
                        svc = OpenService(scm, ServiceName, ServiceAllAccess);
                        if (svc == IntPtr.Zero)
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                }

                try
                {
                    ChangeServiceConfig(
                        svc, ServiceNoChange, ServiceAutoStart, ServiceNoChange,
                        quoted, null, IntPtr.Zero, null, null, null, "Sentinel");
                }
                finally
                {
                    CloseServiceHandle(svc);
                }
            }
            finally
            {
                CloseServiceHandle(scm);
            }
        }

        public static void EnsureAgentRunKey(string agentExePath)
        {
            if (string.IsNullOrWhiteSpace(agentExePath) || !File.Exists(agentExePath))
                return;

            var value = $"\"{Path.GetFullPath(agentExePath)}\"";
            using var key = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", writable: true);
            key?.SetValue(AgentRunValueName, value, RegistryValueKind.String);
        }

        public static void TryStartService()
        {
            var scm = OpenSCManager(null, null, ScManagerAllAccess);
            if (scm == IntPtr.Zero) return;
            try
            {
                var svc = OpenService(scm, ServiceName, ServiceStart | ServiceQueryStatus);
                if (svc == IntPtr.Zero) return;
                try
                {
                    var status = new SERVICE_STATUS();
                    if (QueryServiceStatus(svc, ref status) && status.dwCurrentState == 4 /* RUNNING */)
                        return;
                    StartService(svc, 0, IntPtr.Zero);
                }
                finally { CloseServiceHandle(svc); }
            }
            finally { CloseServiceHandle(scm); }
        }

        public static void TryStopService(int waitMs = 5000)
        {
            var scm = OpenSCManager(null, null, ScManagerAllAccess);
            if (scm == IntPtr.Zero) return;
            try
            {
                var svc = OpenService(scm, ServiceName, ServiceStop | ServiceQueryStatus);
                if (svc == IntPtr.Zero) return;
                try
                {
                    var status = new SERVICE_STATUS();
                    if (!QueryServiceStatus(svc, ref status))
                        return;
                    if (status.dwCurrentState == 1 /* STOPPED */)
                        return;

                    ControlService(svc, ServiceControlStop, ref status);
                    var sw = Stopwatch.StartNew();
                    while (sw.ElapsedMilliseconds < waitMs)
                    {
                        if (QueryServiceStatus(svc, ref status) && status.dwCurrentState == 1)
                            return;
                        System.Threading.Thread.Sleep(200);
                    }
                }
                finally { CloseServiceHandle(svc); }
            }
            finally { CloseServiceHandle(scm); }
        }

        public static void TryLaunchAgent(string agentExePath)
        {
            if (string.IsNullOrWhiteSpace(agentExePath) || !File.Exists(agentExePath))
                return;
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = agentExePath,
                    WorkingDirectory = Path.GetDirectoryName(agentExePath) ?? "",
                    UseShellExecute = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                });
            }
            catch { }
        }
    }
}
