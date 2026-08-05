using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sentinel.Core.Plugins;

namespace Sentinel.Core
{
    /// <summary>
    /// v2.0 — Loads signed correlation rule packs from disk into PluginRegistry.
    ///
    /// Pack location (preferred): %ProgramData%\Sentinel\rules\packs\*.pack.json
    /// Fallback: {installDir}\rules\packs\*.pack.json
    ///
    /// Format:
    /// {
    ///   "name": "example-pack",
    ///   "version": "1.0",
    ///   "rules": [
    ///     {
    ///       "name": "Cred + Network",
    ///       "minSignals": 2,
    ///       "requiredFragments": ["LSASS", "Beacon"],
    ///       "confidence": 0.93,
    ///       "evidence": "Credential access with C2-like network"
    ///     }
    ///   ],
    ///   "hmac": "..."
    /// }
    ///
    /// HMAC-SHA256 over JSON with hmac field removed, key =
    /// HMAC(install_entropy, "sentinel-rule-pack-signing-v1"). Fail-closed without key.
    /// </summary>
    public sealed class RulePackLoader : BackgroundService
    {
        private readonly PluginRegistry _registry;
        private readonly ILogger<RulePackLoader> _logger;
        private readonly string _packsDir;
        private readonly byte[]? _hmacKey;
        private readonly HashSet<string> _loaded = new(StringComparer.OrdinalIgnoreCase);
        private FileSystemWatcher? _watcher;

        public RulePackLoader(PluginRegistry registry, ILogger<RulePackLoader> logger)
        {
            _registry = registry;
            _logger = logger;
            _hmacKey = DeriveSigningKey();

            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            _packsDir = Path.Combine(programData, "Sentinel", "rules", "packs");
        }

        protected override Task ExecuteAsync(CancellationToken stoppingToken)
        {
            try
            {
                if (!Directory.Exists(_packsDir))
                    Directory.CreateDirectory(_packsDir);

                // Also scan install-dir packs if present
                LoadAllPacks();

                _watcher = new FileSystemWatcher(_packsDir, "*.pack.json")
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
                };
                _watcher.Created += (_, _) => SafeReload();
                _watcher.Changed += (_, _) => SafeReload();
                _watcher.EnableRaisingEvents = true;

                _logger.LogInformation("[RulePacks] Watching {Dir} (loaded={Count})",
                    _packsDir, _loaded.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[RulePacks] Init failed — continuing without packs");
            }

            return WaitForeverAsync(stoppingToken);
        }

        private static async Task WaitForeverAsync(CancellationToken ct)
        {
            try { await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { }
        }

        private void SafeReload()
        {
            try { LoadAllPacks(); }
            catch (Exception ex) { _logger.LogDebug(ex, "[RulePacks] Reload error"); }
        }

        public int LoadAllPacks()
        {
            var dirs = new List<string> { _packsDir };
            try
            {
                var installPacks = Path.Combine(AppContext.BaseDirectory, "rules", "packs");
                if (Directory.Exists(installPacks))
                    dirs.Add(installPacks);
            }
            catch { }

            int added = 0;
            foreach (var dir in dirs.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!Directory.Exists(dir)) continue;
                foreach (var file in Directory.EnumerateFiles(dir, "*.pack.json"))
                {
                    if (_loaded.Contains(file)) continue;
                    if (TryLoadPack(file))
                    {
                        _loaded.Add(file);
                        added++;
                    }
                }
            }
            return added;
        }

        /// <summary>Test helper: load a pack file path directly.</summary>
        public bool TryLoadPack(string filePath)
        {
            try
            {
                var content = File.ReadAllText(filePath);
                if (!VerifySignature(content, filePath))
                    return false;

                var pack = JsonSerializer.Deserialize<RulePackFile>(content, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                if (pack?.Rules == null || pack.Rules.Count == 0)
                {
                    _logger.LogWarning("[RulePacks] Empty pack {File}", Path.GetFileName(filePath));
                    return false;
                }

                foreach (var rule in pack.Rules)
                {
                    if (string.IsNullOrWhiteSpace(rule.Name) ||
                        rule.RequiredFragments == null ||
                        rule.RequiredFragments.Count == 0)
                        continue;

                    _registry.Register(new FragmentCorrelationRule(rule, pack.Name));
                    _logger.LogInformation("[RulePacks] Registered correlation rule '{Rule}' from pack '{Pack}'",
                        rule.Name, pack.Name);
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[RulePacks] Failed to load {File}", Path.GetFileName(filePath));
                return false;
            }
        }

        private bool VerifySignature(string fileContent, string filePath)
        {
            if (_hmacKey == null)
            {
                _logger.LogError("[RulePacks] REJECTED {File} — signing key unavailable (fail-closed)",
                    Path.GetFileName(filePath));
                return false;
            }

            try
            {
                using var doc = JsonDocument.Parse(fileContent);
                if (!doc.RootElement.TryGetProperty("hmac", out var hmacEl))
                {
                    _logger.LogWarning("[RulePacks] REJECTED {File} — missing hmac", Path.GetFileName(filePath));
                    return false;
                }
                var provided = hmacEl.GetString();
                if (string.IsNullOrEmpty(provided)) return false;

                var toSign = RemoveHmacField(fileContent);
                using var hmac = new HMACSHA256(_hmacKey);
                var expected = BitConverter.ToString(hmac.ComputeHash(Encoding.UTF8.GetBytes(toSign)))
                    .Replace("-", "").ToLowerInvariant();
                var ok = SecurityValidation.SecureCompare(
                    Encoding.ASCII.GetBytes(expected),
                    Encoding.ASCII.GetBytes(provided.ToLowerInvariant()));
                if (!ok)
                    _logger.LogWarning("[RulePacks] REJECTED {File} — bad hmac", Path.GetFileName(filePath));
                return ok;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Test-only path: load without HMAC (unit tests).</summary>
        public int LoadPackForTest(RulePackFile pack)
        {
            if (pack.Rules == null) return 0;
            int n = 0;
            foreach (var rule in pack.Rules)
            {
                if (rule.RequiredFragments == null || rule.RequiredFragments.Count == 0) continue;
                _registry.Register(new FragmentCorrelationRule(rule, pack.Name ?? "test"));
                n++;
            }
            return n;
        }

        private static string RemoveHmacField(string json)
        {
            using var doc = JsonDocument.Parse(json);
            using var ms = new MemoryStream();
            using (var writer = new Utf8JsonWriter(ms))
            {
                writer.WriteStartObject();
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    if (prop.NameEquals("hmac")) continue;
                    prop.WriteTo(writer);
                }
                writer.WriteEndObject();
            }
            return Encoding.UTF8.GetString(ms.ToArray());
        }

        private static byte[]? DeriveSigningKey()
        {
            try
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var entropyFile = Path.Combine(programData, "Sentinel", "Secure", ".install_entropy");
                if (!File.Exists(entropyFile)) return null;
                var entropy = File.ReadAllBytes(entropyFile);
                if (entropy.Length != 32) return null;
                using var hmac = new HMACSHA256(entropy);
                return hmac.ComputeHash(Encoding.UTF8.GetBytes("sentinel-rule-pack-signing-v1"));
            }
            catch { return null; }
        }

        public override void Dispose()
        {
            _watcher?.Dispose();
            base.Dispose();
        }
    }

    public sealed class RulePackFile
    {
        public string Name { get; set; } = "pack";
        public string Version { get; set; } = "1.0";
        public List<RulePackCorrelationRule> Rules { get; set; } = new();
        public string? Hmac { get; set; }
    }

    public sealed class RulePackCorrelationRule
    {
        public string Name { get; set; } = "";
        public int MinSignals { get; set; } = 2;
        public List<string> RequiredFragments { get; set; } = new();
        public double Confidence { get; set; } = 0.92;
        public string Evidence { get; set; } = "Rule pack multi-signal match";
        public string Reasoning { get; set; } = "Signed rule pack correlation matched required fragments on one process.";
        public List<string>? AttackTechniques { get; set; }
    }

    /// <summary>
    /// Correlation rule from a signed pack: all RequiredFragments must appear in
    /// distinct rule names within the PID signal buffer (case-insensitive Contains).
    /// </summary>
    public sealed class FragmentCorrelationRule : ICorrelationRule
    {
        private readonly RulePackCorrelationRule _def;
        private readonly string _packName;

        public FragmentCorrelationRule(RulePackCorrelationRule def, string packName)
        {
            _def = def;
            _packName = packName;
        }

        public string Name => $"Pack:{_packName}:{_def.Name}";
        public double MinConfidence => _def.Confidence;

        public DetectionEvent? Evaluate(int processId, string processName, IReadOnlyList<DetectionEvent> signals)
        {
            if (signals == null || signals.Count < Math.Max(2, _def.MinSignals))
                return null;
            if (_def.RequiredFragments == null || _def.RequiredFragments.Count == 0)
                return null;

            var names = signals.Select(s => s.RuleName ?? "").ToList();
            foreach (var frag in _def.RequiredFragments)
            {
                if (string.IsNullOrWhiteSpace(frag)) continue;
                if (!names.Any(n => n.IndexOf(frag, StringComparison.OrdinalIgnoreCase) >= 0))
                    return null;
            }

            var meta = new Dictionary<string, string>
            {
                ["RulePack"] = _packName,
                ["RulePackRule"] = _def.Name,
                [ResponsePolicy.ChainConfirmedKey] = "true",
                [ResponsePolicy.TerminalOutcomeKey] = "Composite",
            };
            if (_def.AttackTechniques != null && _def.AttackTechniques.Count > 0)
                meta["AttackTechniques"] = string.Join(",", _def.AttackTechniques);

            return new DetectionEvent
            {
                RuleName = $"Rule Pack: {_def.Name}",
                ProcessId = processId,
                ProcessName = processName,
                Confidence = Math.Min(0.97, Math.Max(0.85, _def.Confidence)),
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.QuarantineAndKill,
                SignalType = SignalType.SuspiciousProcess,
                Evidence = $"[COMPOSITE] {_def.Evidence} (pack={_packName}, PID {processId})",
                Reasoning = _def.Reasoning,
                Timestamp = DateTime.UtcNow,
                Metadata = meta
            };
        }
    }
}
