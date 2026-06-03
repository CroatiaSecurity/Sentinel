using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core
{
    public sealed class ArpSpoofMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ArpSpoofMonitor> _logger;
        public ArpSpoofMonitor(DetectionEngine de, ILogger<ArpSpoofMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ArpSpoofMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(30000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class BluetoothMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<BluetoothMonitor> _logger;
        public BluetoothMonitor(DetectionEngine de, ILogger<BluetoothMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[BluetoothMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(60000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class CanaryFileMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<CanaryFileMonitor> _logger;
        public CanaryFileMonitor(DetectionEngine de, ILogger<CanaryFileMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[CanaryFileMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(10000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class ChromeCredentialGuardMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ChromeCredentialGuardMonitor> _logger;
        public ChromeCredentialGuardMonitor(DetectionEngine de, ILogger<ChromeCredentialGuardMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ChromeCredentialGuardMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(15000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class ChromeSessionGuardMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ChromeSessionGuardMonitor> _logger;
        public ChromeSessionGuardMonitor(DetectionEngine de, ILogger<ChromeSessionGuardMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ChromeSessionGuardMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(15000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class DeviceInstallMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DeviceInstallMonitor> _logger;
        public DeviceInstallMonitor(DetectionEngine de, ILogger<DeviceInstallMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DeviceInstallMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(30000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class DiskWideDllScanner : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DiskWideDllScanner> _logger;
        public DiskWideDllScanner(DetectionEngine de, ILogger<DiskWideDllScanner> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DiskWideDllScanner] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(120000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class DllEntropyAnalyzer : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DllEntropyAnalyzer> _logger;
        public DllEntropyAnalyzer(DetectionEngine de, ILogger<DllEntropyAnalyzer> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DllEntropyAnalyzer] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(180000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class DllLoadFailureMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DllLoadFailureMonitor> _logger;
        public DllLoadFailureMonitor(DetectionEngine de, ILogger<DllLoadFailureMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DllLoadFailureMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(15000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class DnsResponseValidationMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<DnsResponseValidationMonitor> _logger;
        public DnsResponseValidationMonitor(DetectionEngine de, ILogger<DnsResponseValidationMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DnsResponseValidationMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(10000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class FirefoxCredentialGuardMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<FirefoxCredentialGuardMonitor> _logger;
        public FirefoxCredentialGuardMonitor(DetectionEngine de, ILogger<FirefoxCredentialGuardMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[FirefoxCredentialGuardMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(15000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class FirewallIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<FirewallIntegrityMonitor> _logger;
        public FirewallIntegrityMonitor(DetectionEngine de, ILogger<FirewallIntegrityMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[FirewallIntegrityMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(30000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class GatewayFingerprintMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<GatewayFingerprintMonitor> _logger;
        public GatewayFingerprintMonitor(DetectionEngine de, ILogger<GatewayFingerprintMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[GatewayFingerprintMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(60000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class MicrosoftAccountGuardMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<MicrosoftAccountGuardMonitor> _logger;
        public MicrosoftAccountGuardMonitor(DetectionEngine de, ILogger<MicrosoftAccountGuardMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[MicrosoftAccountGuardMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(30000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class ModuleValidationMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ModuleValidationMonitor> _logger;
        public ModuleValidationMonitor(DetectionEngine de, ILogger<ModuleValidationMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ModuleValidationMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(30000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class PublicIpMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<PublicIpMonitor> _logger;
        public PublicIpMonitor(DetectionEngine de, ILogger<PublicIpMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[PublicIpMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(300000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class RemoteAccessMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<RemoteAccessMonitor> _logger;
        public RemoteAccessMonitor(DetectionEngine de, ILogger<RemoteAccessMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[RemoteAccessMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(15000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class RuntimeModuleIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<RuntimeModuleIntegrityMonitor> _logger;
        public RuntimeModuleIntegrityMonitor(DetectionEngine de, ILogger<RuntimeModuleIntegrityMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[RuntimeModuleIntegrityMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(60000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class ScheduledTaskMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<ScheduledTaskMonitor> _logger;
        public ScheduledTaskMonitor(DetectionEngine de, ILogger<ScheduledTaskMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[ScheduledTaskMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(30000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class SecureBootIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<SecureBootIntegrityMonitor> _logger;
        public SecureBootIntegrityMonitor(DetectionEngine de, ILogger<SecureBootIntegrityMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[SecureBootIntegrityMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(300000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class SyscallStubMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<SyscallStubMonitor> _logger;
        public SyscallStubMonitor(DetectionEngine de, ILogger<SyscallStubMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[SyscallStubMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(30000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class TlsCertificateMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<TlsCertificateMonitor> _logger;
        public TlsCertificateMonitor(DetectionEngine de, ILogger<TlsCertificateMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[TlsCertificateMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(60000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class UacBypassSurfaceMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<UacBypassSurfaceMonitor> _logger;
        public UacBypassSurfaceMonitor(DetectionEngine de, ILogger<UacBypassSurfaceMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[UacBypassSurfaceMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(15000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class WifiSecurityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WifiSecurityMonitor> _logger;
        public WifiSecurityMonitor(DetectionEngine de, ILogger<WifiSecurityMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WifiSecurityMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(60000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class WindowsUpdateIntegrityMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WindowsUpdateIntegrityMonitor> _logger;
        public WindowsUpdateIntegrityMonitor(DetectionEngine de, ILogger<WindowsUpdateIntegrityMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WindowsUpdateIntegrityMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(600000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class WmiPersistenceMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WmiPersistenceMonitor> _logger;
        public WmiPersistenceMonitor(DetectionEngine de, ILogger<WmiPersistenceMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WmiPersistenceMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(30000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class WorkFoldersExfilMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WorkFoldersExfilMonitor> _logger;
        public WorkFoldersExfilMonitor(DetectionEngine de, ILogger<WorkFoldersExfilMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WorkFoldersExfilMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(30000, ct); } catch (OperationCanceledException) { break; } }
        }
    }

    public sealed class AdsDataStagingMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<AdsDataStagingMonitor> _logger;
        public AdsDataStagingMonitor(DetectionEngine de, ILogger<AdsDataStagingMonitor> l) { _detectionEngine = de; _logger = l; }
        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[AdsDataStagingMonitor] Started");
            while (!ct.IsCancellationRequested) { try { await Task.Delay(30000, ct); } catch (OperationCanceledException) { break; } }
        }
    }
}
