using System;
using System.Runtime.InteropServices;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using WindowsSentinel.Core;

namespace WindowsSentinel.Agent
{
    public class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeConsole();

        [STAThread]
        public static void Main(string[] args)
        {
            // Apply DLL search path hardening early
            HardeningModule.ApplyOrFail();

            // FreeConsole on startup to detach from parent CLI window
            try
            {
                FreeConsole();
            }
            catch
            {
                // Degrade gracefully if not launched from console
            }

            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureServices((hostContext, services) =>
                {
                    var config = new SentinelConfig();
                    hostContext.Configuration.GetSection("Sentinel").Bind(config);
                    services.AddSingleton(config);
                    services.AddHostedService<TrayIconService>();
                });
    }
}
