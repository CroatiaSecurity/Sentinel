using System;

namespace Sentinel.Core
{
    /// <summary>
    /// Standing product law (v1.9.7+). Read this before adding any host mutation.
    ///
    /// <para><b>DEFAULT = OBSERVE / WORK-FIRST.</b> Users must be free to run NTLite, RDP,
    /// installers, Office macros, USB tools, casting, DISM/RPC, games, etc.</para>
    ///
    /// <para>Proactive OS reshaping (IPSec, firewall blocks, service disable, ASR Block re-arm,
    /// RDP force-logoff, USB auto-disable, deleting Windows firewall rules, …) is forbidden
    /// unless the user explicitly enables kiosk lockdown via
    /// <see cref="SentinelConfig.RestrictivePortHardening"/>.</para>
    ///
    /// <para>Allowed without that flag:</para>
    /// <list type="bullet">
    /// <item>Self-protect Sentinel (DLL path, install ACLs, Safe Mode registration)</item>
    /// <item>Detect + log to events.jsonl</item>
    /// <item>Destructive response only after multi-signal chain confirmation
    ///       (<see cref="ResponsePolicy"/> / ObserveUntilChain)</item>
    /// <item>Proven hostile DLL unload only for classic sideload targets — never OS servicing
    ///       (DismHost/NTLite/TrustedInstaller) or arbitrary Temp modules</item>
    /// <item>Undo our own prior lockdown leftovers (<see cref="HardeningModule.ReleaseUserWorkSurface"/>)</item>
    /// </list>
    ///
    /// <para>If you are about to block a port, disable a service, force-logoff a session,
    /// or re-arm ASR Block by default — <b>stop</b>. Put it behind
    /// <see cref="AllowsProactiveHostLockdown"/> or you will re-break user work and violate constraints.md.</para>
    /// </summary>
    public static class ProductPosture
    {
        /// <summary>
        /// True only when the operator opted into kiosk / restrictive lockdown.
        /// Default false = observe-only host surface.
        /// </summary>
        public static bool AllowsProactiveHostLockdown(SentinelConfig? config)
        {
            if (config != null)
                return config.RestrictivePortHardening;
            return HardeningModule.RestrictivePortHardeningEnabled;
        }

        /// <summary>
        /// Call at the start of any new proactive host-mutation feature.
        /// Returns false in default observe mode — caller must LogOnly / skip.
        /// </summary>
        public static bool TryProactiveHostLockdown(SentinelConfig? config, out string denyReason)
        {
            if (AllowsProactiveHostLockdown(config))
            {
                denyReason = "";
                return true;
            }

            denyReason =
                "ProductPosture: proactive host lockdown denied (default observe/work-first). " +
                "Set RestrictivePortHardening=true for kiosk mode, or respond only via chain-confirmed detection.";
            return false;
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
    }
}
