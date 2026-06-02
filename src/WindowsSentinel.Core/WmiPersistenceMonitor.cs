using System.Management;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core;

/// <summary>
/// Periodically scans the WMI namespace for event subscription persistence
/// (__EventFilter + __EventConsumer + __FilterToConsumerBinding).
///
/// WMI event subscriptions are a stealthy persistence mechanism (MITRE T1546.003)
/// that survives reboots and is invisible to registry/file-based monitors.
/// Used by APT groups, fileless malware, and frameworks like:
///   - Cobalt Strike (WMI persistence module)
///   - Empire (Invoke-WMIPersistence)
///   - SEABORGIUM / COLDRIVER campaigns
///   - APT29 (HAMMERTOSS)
///
/// This monitor detects EXISTING subscriptions (already planted), complementing
/// the PersistenceRule which only catches the creation command at runtime.
/// </summary>
public sealed class WmiPersistenceMonitor : BackgroundService
{
    private readonly DetectionEngine _detectionEngine;
    private readonly ILogger<WmiPersistenceMonitor> _logger;

    // Known legitimate WMI subscriptions (Windows built-in)
    private static readonly HashSet<string> SafeFilterNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "SCM Event Log Filter",
        "BVTFilter",
        "TSLogonFilter",
        "RAevent",
        "RmAssistEventFilter",
        "INTELSME_FILTER",
    };

    // Known legitimate consumer names
    private static readonly HashSet<string> SafeConsumerNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "SCM Event Log Consumer",
        "BVTConsumer",
        "TSLogonEvents",
        "NTEventLogEventConsumer",
        "INTELSME_CONSUMER",
    };

    // Track previously seen subscriptions to avoid re-alerting
    private readonly HashSet<string> _knownSubscriptions = new(StringComparer.OrdinalIgnoreCase);

    public WmiPersistenceMonitor(
        DetectionEngine detectionEngine,
        ILogger<WmiPersistenceMonitor> logger)
    {
        _detectionEngine = detectionEngine;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("[WmiPersistenceMonitor] Starting WMI event subscription surveillance.");

        // Initial delay to let the system settle
        await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);

        // Initial scan
        await ScanWmiSubscriptionsAsync(stoppingToken);

        // Periodic re-scan every 5 minutes
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
                await ScanWmiSubscriptionsAsync(stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[WmiPersistenceMonitor] Scan error.");
                await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
            }
        }
    }

    private async Task ScanWmiSubscriptionsAsync(CancellationToken ct)
    {
        var filters = GetWmiObjects("root\\subscription", "SELECT * FROM __EventFilter");
        var consumers = GetWmiObjects("root\\subscription", "SELECT * FROM __EventConsumer");
        var bindings = GetWmiObjects("root\\subscription", "SELECT * FROM __FilterToConsumerBinding");

        // Check for suspicious event filters
        foreach (var filter in filters)
        {
            ct.ThrowIfCancellationRequested();

            var filterName = filter.GetValueOrDefault("Name", "Unknown");
            var query = filter.GetValueOrDefault("QueryLanguage", "") + ": " +
                       filter.GetValueOrDefault("Query", "");

            if (SafeFilterNames.Contains(filterName)) continue;

            var key = $"Filter:{filterName}";
            if (_knownSubscriptions.Contains(key)) continue;
            _knownSubscriptions.Add(key);

            _logger.LogWarning(
                "[WmiPersistenceMonitor] Suspicious WMI EventFilter: '{Name}' Query: {Query}",
                filterName, query);

            await EmitDetection(
                $"WMI Persistence: Suspicious EventFilter '{filterName}'",
                $"WMI __EventFilter found in root\\subscription namespace. " +
                $"Name: '{filterName}', Query: '{query}'",
                filterName, "EventFilter", query, ct);
        }

        // Check for suspicious event consumers (especially ActiveScript and CommandLine)
        foreach (var consumer in consumers)
        {
            ct.ThrowIfCancellationRequested();

            var consumerName = consumer.GetValueOrDefault("Name", "Unknown");
            var consumerClass = consumer.GetValueOrDefault("__CLASS", "Unknown");

            if (SafeConsumerNames.Contains(consumerName)) continue;

            var key = $"Consumer:{consumerName}";
            if (_knownSubscriptions.Contains(key)) continue;
            _knownSubscriptions.Add(key);

            // ActiveScriptEventConsumer and CommandLineEventConsumer are high-risk
            var isHighRisk = consumerClass.Contains("ActiveScript", StringComparison.OrdinalIgnoreCase) ||
                            consumerClass.Contains("CommandLine", StringComparison.OrdinalIgnoreCase);

            var commandLine = consumer.GetValueOrDefault("CommandLineTemplate", "");
            var scriptText = consumer.GetValueOrDefault("ScriptText", "");
            var payload = !string.IsNullOrEmpty(commandLine) ? commandLine :
                         !string.IsNullOrEmpty(scriptText) ? scriptText[..Math.Min(200, scriptText.Length)] : "";

            _logger.LogWarning(
                "[WmiPersistenceMonitor] Suspicious WMI Consumer: '{Name}' Class: {Class}",
                consumerName, consumerClass);

            await EmitDetection(
                $"WMI Persistence: {(isHighRisk ? "HIGH RISK " : "")}EventConsumer '{consumerName}'",
                $"WMI {consumerClass} found. Name: '{consumerName}'" +
                (!string.IsNullOrEmpty(payload) ? $", Payload: '{payload}'" : ""),
                consumerName, consumerClass, payload,
                ct, confidence: isHighRisk ? 0.92 : 0.80);
        }

        // Check for bindings (the glue that activates persistence)
        foreach (var binding in bindings)
        {
            ct.ThrowIfCancellationRequested();

            var filterRef = binding.GetValueOrDefault("Filter", "");
            var consumerRef = binding.GetValueOrDefault("Consumer", "");

            var key = $"Binding:{filterRef}->{consumerRef}";
            if (_knownSubscriptions.Contains(key)) continue;
            _knownSubscriptions.Add(key);

            // Extract names from references
            var filterName = ExtractNameFromRef(filterRef);
            var consumerName = ExtractNameFromRef(consumerRef);

            if (SafeFilterNames.Contains(filterName) && SafeConsumerNames.Contains(consumerName))
                continue;

            _logger.LogWarning(
                "[WmiPersistenceMonitor] WMI Binding: Filter '{Filter}' -> Consumer '{Consumer}'",
                filterName, consumerName);

            await EmitDetection(
                $"WMI Persistence: Active Binding '{filterName}' -> '{consumerName}'",
                $"__FilterToConsumerBinding links EventFilter '{filterName}' to " +
                $"EventConsumer '{consumerName}'. This binding activates the persistence mechanism.",
                $"{filterName}->{consumerName}", "FilterToConsumerBinding", "",
                ct, confidence: 0.88);
        }
    }

    private async Task EmitDetection(
        string ruleName, string evidence, string entityName,
        string persistenceType, string payload,
        CancellationToken ct, double confidence = 0.85)
    {
        var detection = new DetectionEvent
        {
            RuleName = ruleName,
            Evidence = evidence,
            Reasoning = "WMI event subscriptions (T1546.003) are a stealthy persistence mechanism " +
                       "that executes arbitrary code in response to system events. They survive reboots, " +
                       "are invisible to file/registry monitors, and are favored by APT groups. " +
                       "ActiveScriptEventConsumer and CommandLineEventConsumer allow arbitrary " +
                       "code execution without touching disk.",
            Confidence = confidence,
            Tier = DetectionTier.Tier1Behavioral,
            ProcessName = "WmiPrvSE.exe",
            ProcessId = 0,
            Timestamp = DateTime.UtcNow,
            Metadata = new Dictionary<string, string>
            {
                ["PersistenceType"] = persistenceType,
                ["EntityName"] = entityName,
                ["Payload"] = payload.Length > 500 ? payload[..500] : payload,
                ["MitreAttack"] = "T1546.003"
            }
        };

        await _detectionEngine.EmitAsync(detection);
    }

    private static List<Dictionary<string, string>> GetWmiObjects(string scope, string query)
    {
        var results = new List<Dictionary<string, string>>();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                new ManagementScope(scope), new ObjectQuery(query));

            using var collection = searcher.Get();
            foreach (ManagementObject obj in collection)
            {
                var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var prop in obj.Properties)
                {
                    dict[prop.Name] = prop.Value?.ToString() ?? "";
                }
                // Include the class name
                dict["__CLASS"] = obj.ClassPath.ClassName;
                results.Add(dict);
                obj.Dispose();
            }
        }
        catch
        {
            // WMI namespace may not exist or be inaccessible â€” not an error
        }

        return results;
    }

    private static string ExtractNameFromRef(string wmiRef)
    {
        // WMI references look like: \\.\root\subscription:__EventFilter.Name="FilterName"
        var nameStart = wmiRef.IndexOf("Name=\"", StringComparison.OrdinalIgnoreCase);
        if (nameStart < 0) return wmiRef;

        nameStart += 6; // Skip past Name="
        var nameEnd = wmiRef.IndexOf('"', nameStart);
        return nameEnd > nameStart ? wmiRef[nameStart..nameEnd] : wmiRef;
    }
}
