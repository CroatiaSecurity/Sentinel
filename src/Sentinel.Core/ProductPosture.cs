using System;

namespace Sentinel.Core
{
    /// <summary>
    /// Standing product law (v2.6.0+). Read this before adding any host mutation.
    ///
    /// <para><b>HARDENING IS ALWAYS-ON.</b> All proactive OS protections (IPSec, firewall blocks,
    /// service lockdown, ASR Block, registry hardening, credential hardening, browser hardening,
    /// LGPO security policy) run unconditionally on every Sentinel startup. There is no
    /// work-first / observe-only mode. The <c>RestrictivePortHardening</c> config toggle has
    /// been removed.</para>
    ///
    /// <para>Always allowed:</para>
    /// <list type="bullet">
    /// <item>Self-protect Sentinel (DLL path, install ACLs, Safe Mode registration)</item>
    /// <item>Detect + log to events.jsonl</item>
    /// <item>Destructive response only after multi-signal chain confirmation
    ///       (<see cref="ResponsePolicy"/> / ObserveUntilChain)</item>
    /// <item>Module identity unload is always on. Foreign mapped PEs are FreeLibrary'd.
    ///       Hijack-name plants are quarantined on drop (file only, never kill the host).
    ///       Games are not VM_READ. Never OS servicing. No config flag may disable this.</item>
    /// <item>All proactive hardening unconditionally applied at startup.</item>
    /// </list>
    /// </summary>
    public static class ProductPosture
    {
        /// <summary>
        /// Standing law: <c>MemoryBehaviorAnalyzer</c> + <c>ModuleIdentity</c> +
        /// <c>DllUnloadEngine</c> scan every process and unload foreign mapped PEs
        /// immediately. There is no config switch. Games/anti-cheat are skipped only
        /// for handle safety (Denuvo). OS servicing / lsass / csrss are never FreeLibrary'd.
        /// </summary>
        public const bool ModuleIdentityUnloadAlwaysOn = true;

        /// <summary>
        /// v2.6.0: Always returns true — hardening is unconditionally enabled.
        /// The config parameter is accepted for call-site compatibility but ignored.
        /// </summary>
        public static bool AllowsProactiveHostLockdown(SentinelConfig? config) => true;

        /// <summary>
        /// v2.6.0: Always succeeds — hardening is unconditionally enabled.
        /// The config parameter is accepted for call-site compatibility but ignored.
        /// </summary>
        public static bool TryProactiveHostLockdown(SentinelConfig? config, out string denyReason)
        {
            denyReason = "";
            return true;
        }

        /// <summary>
        /// Destructive response after detection pipeline — separate from proactive lockdown.
        /// Still gated by ActiveResponse + ObserveUntilChain / chain confirm.
        /// </summary>
        public static bool AllowsChainConfirmedResponse(SentinelConfig? config, DetectionEvent? detection)
        {
            if (config == null || !config.ActiveResponse || detection == null)
                return false;
            return ResponsePolicy.MayPerformDestructiveResponse(detection, config);
        }

        /// <summary>
        /// v1.9.10: Narrow post-incident MITM suite (cert remove, FCM Send-Tab-to-Self block,
        /// rogue Cast / fake Chromecast firewall). Explicit operator opt-in via
        /// <see cref="MitmDefenseConfig.Enabled"/> — independent of hardening always-on.
        /// </summary>
        public static bool AllowsMitmDefenseMutations(SentinelConfig? config)
        {
            return config != null
                   && config.ActiveResponse
                   && config.MitmDefense != null
                   && config.MitmDefense.Enabled;
        }
    }
}
