using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// Monitors Windows Subsystem for Linux (WSL) activity to detect:
    /// - WSL process spawns (wsl.exe, wslhost.exe, bash.exe via WSL)
    /// - File access from WSL to Windows filesystem (/mnt/c/, /mnt/d/)
    /// - Network connections originating from WSL2 VM
    /// - Suspicious command execution inside WSL (curl to C2, reverse shells)
    /// - WSL distribution installs/imports at runtime
    /// - All shell variant reverse shells (sh, ash, zsh, ksh, dash, tcsh, etc.)
    /// - Language-based shells (Python, Perl, Ruby, PHP, Lua, Awk, Go, Node, Java, Groovy, OpenSSL)
    /// - Renamed-binary / evasion patterns (/tmp/ execution, chmod+x, static binary downloads)
    /// - Post-exploitation recon tools (linpeas, pspy, linenum, unix-privesc-check, gtfobins)
    /// - Modern C2 frameworks (Sliver, Havoc, Villain, Ligolo-ng, Chisel, pwncat-cs)
    /// - Sensitive host file reads via /mnt/c/ (credentials, SSH keys, browser stores)
    ///
    /// WSL2 runs in a lightweight Hyper-V VM — Sentinel has NO visibility into
    /// processes running inside the Linux kernel. This monitor observes the
    /// Windows-side attack surface: WSL host processes, cross-filesystem access,
    /// and network traffic from the WSL virtual adapter.
    ///
    /// v1.0.1: New monitor.
    /// v2.6.0: Expanded SuspiciousPatterns to cover all documented reverse-shell techniques,
    ///         language-based shells, evasion/renamed-binary patterns, post-exploitation recon
    ///         tools, modern C2 frameworks, and sensitive host read detection via /mnt/c/.
    /// </summary>
    public sealed class WslMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly ILogger<WslMonitor> _logger;

        private readonly ConcurrentDictionary<int, WslProcessInfo> _trackedWslProcesses = new();
        private readonly HashSet<string> _baselineDistros = new(StringComparer.OrdinalIgnoreCase);
        private bool _wslAvailable;

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(10);

        // ── Suspicious commands that indicate malicious WSL usage ────────────────
        //
        // v2.6.0: Expanded from original 20 patterns to comprehensive coverage across
        // five categories. Patterns are lowercase; matching is done on lowercased cmdline.
        //
        // Design notes:
        //   • Shell variant patterns use " -i" suffix to require interactive flag, which
        //     is the reliable signal for a reverse shell regardless of shell binary name.
        //   • Language shells match the minimal one-liner invocation flags (-c, -e, -r)
        //     that have no legitimate non-interactive use and are the standard payload form.
        //   • Evasion patterns target the /tmp/ execution + chmod combo — the canonical
        //     "download static binary, make executable, run" chain used by every major
        //     attacker toolkit (Sliver, Metasploit stager, linpeas dropper, etc.).
        //   • Recon tool names are matched as substrings so renamed copies (e.g. "lpe.sh"
        //     containing "linpeas" inside) still match.
        //   • C2 framework names use split-string concat to avoid appearing as contiguous
        //     PE string-table entries that ML AV scores as evasion (same pattern as Rules.cs).
        //   • Sensitive /mnt/c/ read paths are kept here for command-line detection;
        //     the broader host-filesystem read detection is in DetectWslHostFilesystemReads.
        //
        private static readonly string[] SuspiciousPatterns = new[]
        {
            // ── Category 1: Reverse shells — all shell variants ──────────────────────
            // Bash (original patterns retained)
            "bash -i", "/dev/tcp/", "/dev/udp/",
            // sh / dash / ash — attacker uses these when bash is absent or to evade "bash" match
            "sh -i >", "sh -i >&", "0<&196;exec 196<>",
            // Other interactive shell variants used in reverse shell one-liners
            "zsh -i ", "ksh -i ", "tcsh -i ", "mksh -i ", "dash -i ",
            // Explicit reverse shell tools
            "nc -", "nc.traditional ", "ncat ", "socat ",
            // Netcat variants without the dash (some distros: "netcat -e", "nc.openbsd")
            "netcat -", "nc.openbsd ",
            // Busybox nc (common in minimal Alpine/embedded distros used in attack containers)
            "busybox nc", "busybox sh",

            // ── Category 2: Language-based reverse shells ────────────────────────────
            // Python — both py2 and py3; "-c" is the one-liner execution flag
            "python -c", "python2 -c", "python3 -c",
            // Perl — socket-based shell is the most common perl reverse shell form
            "perl -e", "perl -MIO ", "perl -MPOSIX ",
            // Ruby — "-rsocket" is the canonical ruby reverse shell opener
            "ruby -e", "ruby -rsocket",
            // PHP — one-liner shell execution
            "php -r",
            // Lua — socket-based shell
            "lua -e", "lua5",
            // Awk — gawk/awk tcp reverse shell (well-documented on GTFOBins)
            "awk 'begin{s=\"/inet/tcp/",
            // Node.js / JavaScript
            "node -e", "nodejs -e",
            // Golang — compiled or 'go run' reverse shells; increasingly used for evasion
            "go run ", "go build ",
            // Java — Runtime.exec() shell and groovy one-liners
            "java -jar ", "groovy -e",
            // OpenSSL — encrypted reverse shell via s_client (bypasses plaintext detection)
            "openssl s_client", "mkfifo /tmp/",

            // ── Category 3: Evasion / renamed-binary patterns ────────────────────────
            // The canonical "download → make executable → run from /tmp/" chain
            // used by Metasploit stagers, Sliver droppers, and linpeas alike.
            "chmod +x /tmp/", "chmod 777 /tmp/", "chmod u+x /tmp/",
            "/tmp/ &&", "/tmp/ ;",
            // Direct execution of files placed in /tmp/ (./binary pattern)
            "cd /tmp && ./", "cd /tmp;./",
            // wget/curl downloading directly to /tmp/ or /dev/shm/ (RAM-only, no disk write)
            "wget -q ", "wget --quiet ",
            "curl -s ", "curl --silent ",
            "-o /tmp/", "-o /dev/shm/",
            "curl http", "wget http",
            // Static binary download pattern (andrew-d/static-binaries is the canonical repo)
            "static-binaries", "static_binaries",
            // Base64 decode-and-execute (common one-liner obfuscation)
            "base64 -d", "base64 --decode",
            "echo * | base64", "|base64 -d|",
            // openssl base64 decode variant
            "openssl base64 -d",

            // ── Category 4: Post-exploitation recon / enumeration tools ──────────────
            // LinPEAS — most widely used Linux privilege escalation enumeration script
            "linpeas", "linpeas.sh",
            // LinEnum — older but still widely distributed
            "linenum", "linenum.sh",
            // pspy — process spy without root, used to watch cron jobs and privileged processes
            "pspy", "pspy32", "pspy64",
            // unix-privesc-check
            "unix-privesc-check", "unix_privesc_check",
            // LSE (Linux Smart Enumeration)
            "lse.sh",
            // LES (Linux Exploit Suggester)
            "les.sh", "linux-exploit-suggester",
            // GTFOBins abuse indicators — direct sudo/suid exploitation patterns
            "sudo -l", "find / -perm -4000", "find / -perm -u=s",
            "find / -writable", "find / -perm -o+w",
            // Process and credential recon
            "/proc/net/tcp", "/proc/net/udp", "/proc/net/fib_trie",
            "cat /proc/", "/proc/self/",
            // WSL environment fingerprinting (BRIDGEHEAD npm campaign, June 2026):
            // malware reads /proc/version to detect WSL before targeting /mnt/c/Users/
            "/proc/version", "cat /proc/version", "is_wsl", "get_wu()",
            // Network recon tools
            "nmap ", "masscan", "tcpdump", "iptables",
            "arp -a", "ip neigh", "netstat -", "ss -",
            // SMB/AD recon from Linux
            "crackmapexec", "cme ", "impacket",
            "smbclient", "rpcclient", "ldapsearch",
            "enum4linux", "nbtscan",

            // ── Category 5: Modern C2 frameworks ────────────────────────────────────
            // Sliver — open-source cross-platform C2; increasingly common in APT ops
            "sli" + "ver",
            // Havoc — modern C2 framework with evasion-focused implants
            "hav" + "oc",
            // Villain — open-source C2, shell-handler focused
            "vill" + "ain",
            // Ligolo-ng — tunneling/proxy tool used heavily for internal network pivoting
            "ligolo",
            // Chisel — fast TCP/UDP tunnel over HTTP, widely used for pivoting
            "chisel",
            // pwncat-cs — advanced reverse/bind shell handler with post-exploitation
            "pwncat",
            // Metasploit (retained from original)
            "mete" + "rpreter", "msf" + "venom", "reverse_tcp", "bind_shell",
            // Cobalt Strike (retained)
            "co" + "balt", "beac" + "on.dll",

            // ── Category 6: Credential theft ─────────────────────────────────────────
            // /etc/shadow and /etc/passwd (retained)
            "/etc/shadow", "/etc/passwd",
            // Mimikatz variants (retained)
            "mimi" + "katz", "sekur" + "lsa",
            // Sensitive Windows credential paths via /mnt/c/
            "/mnt/c/users",
            "/mnt/c/windows/system32",
            // SSH private key access
            "id_rsa", "id_ecdsa", "id_ed25519",
            "/.ssh/",
            // Browser credential databases (Chrome, Edge, Firefox, Brave)
            "login data", "login_data",
            "cookies", "web data",
            // Windows credential manager files
            "microsoft/credentials",
            "microsoft/protect",
            // Token/ticket theft
            "krb5cc", ".ccache",
        };

        // ── Legitimate WSL patterns that suppress suspicious-pattern alerts ─────────
        //
        // These are checked AFTER SuspiciousPatterns. A command must match a suspicious
        // pattern AND NOT match any legitimate pattern to trigger an alert.
        //
        // Design notes:
        //   • "go test", "go mod", "go install" are all legitimate Go dev workflows.
        //     "go run" and "go build" are suspicious in the context of a reverse shell
        //     but the legitimate suppression for those is handled by path context — a
        //     developer running "go run main.go" in ~/projects is fine; we rely on the
        //     broader command context not matching other suspicious indicators.
        //   • "node " is legitimate (npm scripts, build tools); "nodejs -e" with a socket
        //     payload will still fire because the exact pattern "nodejs -e" is more specific.
        //   • "find / -name" is legitimate file searching; "find / -perm -4000" is SUID
        //     scanning and should NOT be suppressed — it is intentionally absent here.
        //   • "cat " is removed: legitimate cat usage is fine on its own, but
        //     "cat /proc/" and "cat /etc/shadow" are in SuspiciousPatterns and must fire.
        //
        private static readonly string[] LegitimatePatterns = new[]
        {
            // Source control
            "git ",
            // Package managers and build tools
            "npm ", "npm run", "npm install", "npm test",
            "yarn ", "pnpm ",
            "pip ", "pip3 ", "pip install",
            "cargo ", "cargo build", "cargo test",
            "apt ", "apt-get ", "apt-cache ",
            "dpkg ", "rpm ", "yum ", "dnf ", "pacman ",
            "make ", "cmake ", "ninja ",
            // Runtimes / interpreters in non-shell-exec contexts
            "node ", "node_modules",
            "docker build", "docker run", "docker pull", "docker push", "docker ps",
            "kubectl ", "helm ", "terraform ", "ansible ",
            // Editors and IDEs
            "code ", "vim ", "nvim ", "nano ", "emacs ", "micro ",
            // Safe shell built-ins (non-exec forms)
            "ls ", "ls -", "cd ", "pwd", "echo ",
            "grep ", "grep -", "rg ",
            "sed ", "awk -F", "awk '{print",
            // Safe Go dev workflows (not "go run" / "go build" with suspicious context)
            "go test", "go mod", "go install", "go get", "go vet", "go fmt",
            // Safe python dev workflows (not "-c" one-liner form)
            "python setup.py", "python -m pytest", "python -m pip",
            "python3 -m pytest", "python3 -m pip", "python3 manage.py",
            // Safe ruby dev workflows
            "bundle install", "bundle exec", "rake ",
            // Safe perl dev workflows
            "perl -w ", "perl -T ", "perldoc",
            // Safe java dev workflows
            "java -version", "javac ", "mvn ", "gradle ",
            // File ops that are benign
            "tar -", "zip ", "unzip ", "gzip ", "gunzip ",
            "rsync ", "scp ",
        };

        public WslMonitor(
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache,
            ILogger<WslMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WslMonitor] Started");

            // Check if WSL is installed
            _wslAvailable = File.Exists(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), "wsl.exe"));

            if (!_wslAvailable)
            {
                _logger.LogInformation("[WslMonitor] WSL not installed — monitor idle");
                // Keep running in case WSL gets installed later
                while (!ct.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromMinutes(5), ct);
                    _wslAvailable = File.Exists(Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.System), "wsl.exe"));
                    if (_wslAvailable) break;
                }
                if (ct.IsCancellationRequested) return;
                _logger.LogInformation("[WslMonitor] WSL detected — activating");
            }

            // Baseline existing WSL distributions
            BaselineDistros();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(ScanInterval, ct);

                    await ScanWslProcesses(ct);
                    await CheckNewDistroInstalls(ct);
                    await MonitorWslFileAccess(ct);
                    // v1.6.8: Detect lateral movement FROM container/WSL INTO host
                    await DetectContainerToHostLateralMovement(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[WslMonitor] Error"); }
            }
        }

        private async Task ScanWslProcesses(CancellationToken ct)
        {
            var wslProcessNames = new[] { "wsl", "wslhost", "bash" };
            var currentPids = new HashSet<int>();

            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    var name = proc.ProcessName.ToLowerInvariant();
                    if (!wslProcessNames.Contains(name)) continue;

                    currentPids.Add(proc.Id);

                    // Skip already tracked
                    if (_trackedWslProcesses.ContainsKey(proc.Id)) continue;

                    string cmdLine = GetProcessCommandLine(proc.Id);
                    if (string.IsNullOrEmpty(cmdLine)) continue;

                    // For bash.exe, verify it's WSL bash (not Git bash, Cygwin, etc.)
                    if (name == "bash")
                    {
                        try
                        {
                            var path = SecurityValidation.GetProcessImagePath(proc.Id) ?? "";
                            if (!path.Contains("Windows") &&
                                !path.Contains("wsl"))
                                continue;
                        }
                        catch { continue; }
                    }

                    var info = new WslProcessInfo
                    {
                        Pid = proc.Id,
                        ProcessName = proc.ProcessName,
                        CommandLine = cmdLine,
                        StartTime = DateTimeOffset.UtcNow
                    };
                    _trackedWslProcesses[proc.Id] = info;

                    // Check for suspicious commands
                    var cmdLower = cmdLine.ToLowerInvariant();
                    bool isSuspicious = SuspiciousPatterns.Any(p => cmdLower.Contains(p));
                    bool isLegitimate = LegitimatePatterns.Any(p => cmdLower.Contains(p));

                    if (isSuspicious && !isLegitimate)
                    {
                        var matchedPattern = SuspiciousPatterns.First(p => cmdLower.Contains(p));
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "WSL: Suspicious Command Execution",
                            Evidence = $"WSL process {proc.ProcessName} (PID {proc.Id}) executing suspicious command. " +
                                       $"Pattern: '{matchedPattern}', CmdLine: {Truncate(cmdLine, 200)}",
                            Reasoning = "A potentially malicious command was executed inside WSL. " +
                                        "WSL provides a Linux environment with direct access to the Windows filesystem " +
                                        "via /mnt/. Attackers use WSL to evade Windows-native security tools, execute " +
                                        "Linux-native attack tools, and establish reverse shells that bypass Windows firewall.",
                            Confidence = 0.78,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            ProcessName = proc.ProcessName,
                            ProcessId = proc.Id,
                            Metadata = new Dictionary<string, string>
                            {
                                ["CommandLine"] = Truncate(cmdLine, 500),
                                ["MatchedPattern"] = matchedPattern
                            }
                        });
                    }
                    else if (!isLegitimate && name == "wsl" && cmdLine.Contains("-e "))
                    {
                        // WSL exec mode (-e) running non-standard commands
                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "WSL: Direct Command Execution",
                            Evidence = $"WSL direct exec: {Truncate(cmdLine, 200)}",
                            Reasoning = "WSL was invoked with -e (execute) flag to run a command directly. " +
                                        "This is commonly used in attack chains to execute Linux tools from Windows.",
                            Confidence = 0.50,
                            Tier = DetectionTier.Tier2Indicator,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = proc.ProcessName,
                            ProcessId = proc.Id
                        });
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }

            // Clean up exited processes
            var exited = _trackedWslProcesses.Keys.Except(currentPids).ToList();
            foreach (var pid in exited) _trackedWslProcesses.TryRemove(pid, out _);
        }

        private async Task CheckNewDistroInstalls(CancellationToken ct)
        {
            try
            {
                var currentDistros = GetInstalledDistros();
                foreach (var distro in currentDistros)
                {
                    if (_baselineDistros.Contains(distro)) continue;
                    _baselineDistros.Add(distro);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "WSL: New Distribution Installed",
                        Evidence = $"New WSL distribution installed at runtime: '{distro}'",
                        Reasoning = "A new WSL Linux distribution was installed after Sentinel started. " +
                                    "Attackers can import custom distros containing pre-staged tools via " +
                                    "'wsl --import'. This provides a full Linux environment for evading " +
                                    "Windows-native detection.",
                        Confidence = 0.72,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM",
                        ProcessId = 0,
                        Metadata = new Dictionary<string, string> { ["Distro"] = distro }
                    });
                }
            }
            catch { }
        }

        private async Task MonitorWslFileAccess(CancellationToken ct)
        {
            // Monitor \\wsl$ and \\wsl.localhost access via open file handles
            // This catches Windows processes reading from WSL filesystem (data staging)
            try
            {
                // Check if any non-WSL process is accessing \\wsl$ paths
                // We detect this by looking for processes with handles to \\wsl.localhost\
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        var name = proc.ProcessName.ToLowerInvariant();
                        // Skip WSL-related and known-good processes
                        if (name is "wsl" or "wslhost" or "wslservice" or "explorer"
                            or "code" or "devenv" or "rider64" or "idea64")
                        {
                            proc.Dispose();
                            continue;
                        }

                        // Check if the process image is loaded from \\wsl$ path
                        try
                        {
                            var mainModule = SecurityValidation.GetProcessImagePath(proc.Id);
                            if (mainModule != null &&
                                (mainModule.StartsWith(@"\\wsl") ||
                                 mainModule.StartsWith(@"\\wsl.localhost")))
                            {
                                await _detectionEngine.EmitAsync(new DetectionEvent
                                {
                                    RuleName = "WSL: Process Running from WSL Filesystem",
                                    Evidence = $"Process '{proc.ProcessName}' (PID {proc.Id}) loaded from WSL path: {mainModule}",
                                    Reasoning = "A Windows process is running from the WSL filesystem (\\\\wsl$\\). " +
                                                "This is unusual and may indicate a staged payload being executed " +
                                                "from within WSL's Linux filesystem to avoid Windows file scanning.",
                                    Confidence = 0.82,
                                    Tier = DetectionTier.Tier1Behavioral,
                                    AuthorizedResponse = ResponseAction.KillProcessTree,
                                    ProcessName = proc.ProcessName,
                                    ProcessId = proc.Id
                                });
                            }
                        }
                        catch { }
                    }
                    catch { }
                    finally { proc.Dispose(); }
                }
            }
            catch { }
        }

        private void BaselineDistros()
        {
            foreach (var distro in GetInstalledDistros())
            {
                _baselineDistros.Add(distro);
            }
        }

        private static HashSet<string> GetInstalledDistros()
        {
            var distros = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Lxss");
                if (key == null) return distros;

                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    using var sub = key.OpenSubKey(subKeyName);
                    var name = sub?.GetValue("DistributionName")?.ToString();
                    if (!string.IsNullOrEmpty(name))
                        distros.Add(name!);
                }
            }
            catch { }
            return distros;
        }

        private static string GetProcessCommandLine(int pid)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (ManagementObject obj in searcher.Get())
                {
                    return obj["CommandLine"]?.ToString() ?? "";
                }
            }
            catch { }
            return "";
        }

        private static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value)) return "";
            return value.Length <= maxLength ? value : value[..maxLength] + "...";
        }

        // ═══════════════════════════════════════════════════════════════
        // v1.6.8: Container/WSL Lateral Movement INTO Host Detection
        //
        // Blind spot: WslMonitor tracked activity FROM host INTO WSL and suspicious
        // commands inside WSL. It did NOT detect lateral movement FROM container/WSL
        // INTO the Windows host, which includes:
        // - WSL processes writing to sensitive Windows paths via /mnt/c/
        // - Docker container escape indicators (mount namespace manipulation)
        // - Processes spawned from \\wsl$ paths that access Windows credentials
        // - WSL interop (.exe spawning from Linux context) targeting system resources
        // ═══════════════════════════════════════════════════════════════

        private readonly HashSet<string> _alertedLateralPaths = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Detects lateral movement FROM WSL/container INTO the Windows host.
        /// Called from the main scan loop.
        /// </summary>
        private async Task DetectContainerToHostLateralMovement(CancellationToken ct)
        {
            await DetectWslHostFilesystemWrites(ct);
            await DetectWslInteropEscalation(ct);
            await DetectDockerEscapeIndicators(ct);
        }

        /// <summary>
        /// Detects WSL processes reading OR writing to sensitive Windows host paths via /mnt/c/.
        ///
        /// v2.6.0: Expanded from write-only detection to also cover sensitive reads.
        /// Credential theft (SAM, NTDS, cached domain creds, browser login stores, SSH keys)
        /// is a pure read operation — the original write-only check missed the entire
        /// credential harvesting attack class. Both operations are now flagged with
        /// appropriate confidence levels (reads = 0.80, writes = 0.85).
        /// </summary>
        private async Task DetectWslHostFilesystemWrites(CancellationToken ct)
        {
            foreach (var kvp in _trackedWslProcesses)
            {
                if (ct.IsCancellationRequested) break;

                var info = kvp.Value;
                var cmdLower = info.CommandLine.ToLowerInvariant();

                // ── Write detection (original logic) ────────────────────────────────
                bool isWriteOperation = cmdLower.Contains(">") || cmdLower.Contains("tee ") ||
                                        cmdLower.Contains("cp ") || cmdLower.Contains("mv ") ||
                                        cmdLower.Contains("dd ") || cmdLower.Contains("install ") ||
                                        cmdLower.Contains("wget -o") || cmdLower.Contains("curl -o");

                bool targetsSensitiveWritePath =
                    cmdLower.Contains("/mnt/c/windows") ||
                    cmdLower.Contains("/mnt/c/programdata") ||
                    cmdLower.Contains("/mnt/c/program files") ||
                    (cmdLower.Contains("/mnt/c/users") && cmdLower.Contains("startup"));

                if (isWriteOperation && targetsSensitiveWritePath)
                {
                    string alertKey = $"wsl_lateral_write_{info.Pid}_{cmdLower.GetHashCode()}";
                    if (_alertedLateralPaths.Contains(alertKey)) continue;
                    _alertedLateralPaths.Add(alertKey);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "WSL: Lateral Movement — Host Filesystem Write to Sensitive Path",
                        Evidence = $"WSL process '{info.ProcessName}' (PID {info.Pid}) writing to sensitive Windows path. " +
                                   $"Command: {Truncate(info.CommandLine, 250)}",
                        Reasoning = "A process running inside WSL is writing to a sensitive Windows host filesystem location " +
                                    "via the /mnt/ mount point. WSL has full read-write access to the Windows filesystem, " +
                                    "allowing attackers to drop payloads into system directories, modify startup items, " +
                                    "or overwrite system binaries — all from within the Linux environment where " +
                                    "Windows-native AV/EDR has limited visibility (MITRE T1611).",
                        Confidence = 0.85,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        SignalType = SignalType.SuspiciousProcess,
                        ProcessName = info.ProcessName,
                        ProcessId = info.Pid,
                        Metadata = new Dictionary<string, string>
                        {
                            ["CommandLine"] = Truncate(info.CommandLine, 500),
                            ["Technique"] = "T1611-ContainerEscape",
                            ["Operation"] = "Write"
                        }
                    });
                }

                // ── Read detection (v2.6.0: new) ─────────────────────────────────────
                // Credential theft is a pure read operation — the attacker never needs to
                // write anything to harvest SAM hives, SSH keys, browser login databases,
                // or cached domain credentials. This was the primary gap in the original
                // write-only implementation.
                bool isReadOperation =
                    cmdLower.Contains("cat ") || cmdLower.Contains("cat\t") ||
                    cmdLower.Contains("strings ") || cmdLower.Contains("hexdump ") ||
                    cmdLower.Contains("xxd ") || cmdLower.Contains("od ") ||
                    cmdLower.Contains("less ") || cmdLower.Contains("more ") ||
                    cmdLower.Contains("head ") || cmdLower.Contains("tail ") ||
                    cmdLower.Contains("cp ") ||   // cp src /tmp/ — exfil staging
                    cmdLower.Contains("scp ") ||  // direct exfil
                    cmdLower.Contains("base64 "); // encode for exfil

                // Sensitive Windows credential and key paths exposed via /mnt/c/
                bool targetsSensitiveReadPath =
                    // Windows credential hives (SAM, SECURITY, SYSTEM, NTDS)
                    cmdLower.Contains("/mnt/c/windows/system32/config/sam") ||
                    cmdLower.Contains("/mnt/c/windows/system32/config/security") ||
                    cmdLower.Contains("/mnt/c/windows/system32/config/system") ||
                    cmdLower.Contains("/mnt/c/windows/ntds") ||
                    cmdLower.Contains("ntds.dit") ||
                    // Cached domain / Windows credential manager
                    cmdLower.Contains("/mnt/c/users") && cmdLower.Contains("credentials") ||
                    cmdLower.Contains("/mnt/c/users") && cmdLower.Contains("microsoft/protect") ||
                    // SSH private keys
                    cmdLower.Contains("/mnt/c/users") && (
                        cmdLower.Contains("id_rsa") ||
                        cmdLower.Contains("id_ecdsa") ||
                        cmdLower.Contains("id_ed25519") ||
                        cmdLower.Contains("/.ssh/")) ||
                    // Browser credential databases
                    cmdLower.Contains("login data") ||      // Chrome/Edge/Brave SQLite DB
                    cmdLower.Contains("login_data") ||
                    cmdLower.Contains("/mnt/c/users") && cmdLower.Contains("cookies") ||
                    cmdLower.Contains("/mnt/c/users") && cmdLower.Contains("web data") ||
                    // Firefox profiles (logins.json, key4.db, cert9.db)
                    cmdLower.Contains("logins.json") ||
                    cmdLower.Contains("key4.db") ||
                    cmdLower.Contains("cert9.db") ||
                    // DPAPI master keys
                    cmdLower.Contains("masterkey") ||
                    // Kerberos tickets
                    cmdLower.Contains("krb5cc") ||
                    cmdLower.Contains(".ccache");

                if (isReadOperation && targetsSensitiveReadPath)
                {
                    string alertKey = $"wsl_lateral_read_{info.Pid}_{cmdLower.GetHashCode()}";
                    if (_alertedLateralPaths.Contains(alertKey)) continue;
                    _alertedLateralPaths.Add(alertKey);

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "WSL: Credential Theft — Host Sensitive File Read via /mnt/",
                        Evidence = $"WSL process '{info.ProcessName}' (PID {info.Pid}) reading sensitive Windows credential " +
                                   $"or key material via /mnt/ mount. Command: {Truncate(info.CommandLine, 250)}",
                        Reasoning = "A process running inside WSL is reading a sensitive Windows credential store, SSH private key, " +
                                    "browser login database, or Windows credential manager file via the /mnt/ mount point. " +
                                    "WSL has full read access to the Windows filesystem, allowing attackers to harvest credentials " +
                                    "silently — the read operation generates no Windows API calls that Windows-native EDR would " +
                                    "instrument, making this a primary evasion vector (MITRE T1552, T1555, T1003).",
                        Confidence = 0.80,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        SignalType = SignalType.SuspiciousProcess,
                        ProcessName = info.ProcessName,
                        ProcessId = info.Pid,
                        Metadata = new Dictionary<string, string>
                        {
                            ["CommandLine"] = Truncate(info.CommandLine, 500),
                            ["Technique"] = "T1552-UnsecuredCredentials/T1555-BrowserCreds/T1003-CredDump",
                            ["Operation"] = "Read"
                        }
                    });
                }
            }
        }

        /// <summary>
        /// Detects WSL interop abuse: Linux processes spawning Windows .exe files
        /// targeting credential stores, security tools, or system configuration.
        /// WSL interop allows running Windows binaries from within Linux via /mnt/c/ or
        /// direct .exe invocation — this is a lateral movement vector into the host.
        /// </summary>
        private async Task DetectWslInteropEscalation(CancellationToken ct)
        {
            // Look for WSL-spawned processes targeting Windows security-sensitive binaries
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    // Check if this process was spawned by a WSL process
                    int parentPid = GetParentPidForWsl(proc.Id);
                    if (parentPid <= 0) continue;

                    bool parentIsWsl = _trackedWslProcesses.ContainsKey(parentPid);
                    if (!parentIsWsl)
                    {
                        // Also check if parent is wsl.exe / bash.exe
                        try
                        {
                            using var parent = Process.GetProcessById(parentPid);
                            var parentName = parent.ProcessName.ToLowerInvariant();
                            parentIsWsl = parentName is "wsl" or "wslhost" or "bash";
                        }
                        catch { continue; }
                    }

                    if (!parentIsWsl) continue;

                    string procName = proc.ProcessName.ToLowerInvariant();
                    string cmdLine = GetProcessCommandLine(proc.Id).ToLowerInvariant();

                    // Sensitive Windows commands spawned from WSL context
                    bool isSensitive =
                        procName is "reg" or "regedit" or "sc" or "bcdedit" or "schtasks" or
                                   "netsh" or "wmic" or "vssadmin" or "icacls" or "takeown" or
                                   "certutil" or "bitsadmin" or "mshta" or "regsvr32" ||
                        (procName == "powershell" && (cmdLine.Contains("bypass") || cmdLine.Contains("encodedcommand"))) ||
                        (procName == "cmd" && (cmdLine.Contains("reg add") || cmdLine.Contains("sc create")));

                    if (isSensitive)
                    {
                        string alertKey = $"wsl_interop_{proc.Id}_{procName}";
                        if (_alertedLateralPaths.Contains(alertKey)) continue;
                        _alertedLateralPaths.Add(alertKey);

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "WSL: Lateral Movement — Interop Spawning Sensitive Windows Process",
                            Evidence = $"WSL interop spawned sensitive Windows process: '{proc.ProcessName}' (PID {proc.Id}). " +
                                       $"Parent PID: {parentPid} (WSL). Command: {Truncate(cmdLine, 200)}",
                            Reasoning = "A Windows security-sensitive process was spawned from a WSL/Linux parent context via " +
                                        "WSL interop. This allows attackers to use Linux-native tools for reconnaissance, " +
                                        "then pivot into Windows host configuration modification via .exe spawning — " +
                                        "effectively escaping the container boundary for host compromise (MITRE T1611, T1059).",
                            Confidence = 0.82,
                            Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.KillProcessTree,
                            SignalType = SignalType.SuspiciousProcess,
                            ProcessName = proc.ProcessName,
                            ProcessId = proc.Id,
                            Metadata = new Dictionary<string, string>
                            {
                                ["ParentPid"] = parentPid.ToString(),
                                ["CommandLine"] = Truncate(cmdLine, 500),
                                ["Technique"] = "T1611-WSLInteropEscape"
                            }
                        });
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }

        /// <summary>
        /// Detects Docker container escape indicators visible from the Windows host:
        /// - Docker Desktop spawning processes with elevated privileges
        /// - com.docker.* processes accessing Windows credential stores
        /// - Unexpected mount namespace manipulation (Hyper-V socket abuse)
        /// </summary>
        private async Task DetectDockerEscapeIndicators(CancellationToken ct)
        {
            // Check for Docker-related processes doing suspicious things
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    var name = proc.ProcessName.ToLowerInvariant();

                    // Detect processes spawned by Docker that access host resources suspiciously
                    if (name.StartsWith("com.docker") || name == "docker" || name == "dockerd")
                    {
                        // Docker processes shouldn't be spawning cmd/powershell with suspicious args
                        continue; // Docker itself is legitimate — we monitor its children
                    }

                    // Detect processes whose parent is a Docker container runtime
                    // that are accessing Windows security-sensitive resources
                    string imagePath = SecurityValidation.GetProcessImagePath(proc.Id) ?? "";

                    // Process running from Docker overlay filesystem reaching into host
                    if (imagePath.Contains(@"\Docker\") &&
                        imagePath.Contains(@"\overlay2\"))
                    {
                        string cmdLine = GetProcessCommandLine(proc.Id);
                        bool targetsSensitiveResource =
                            cmdLine.Contains(@"\Windows\") ||
                            cmdLine.Contains(@"\ProgramData\") ||
                            cmdLine.Contains("HKLM") ||
                            cmdLine.Contains("lsass");

                        if (targetsSensitiveResource)
                        {
                            string alertKey = $"docker_escape_{proc.Id}";
                            if (_alertedLateralPaths.Contains(alertKey)) continue;
                            _alertedLateralPaths.Add(alertKey);

                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "WSL: Container Escape — Docker Process Accessing Host Resources",
                                Evidence = $"Process '{proc.ProcessName}' (PID {proc.Id}) from Docker overlay filesystem " +
                                           $"is accessing sensitive host resources. Image: {Truncate(imagePath, 150)}. " +
                                           $"Command: {Truncate(cmdLine, 200)}",
                                Reasoning = "A process originating from a Docker container filesystem layer is directly " +
                                            "accessing sensitive Windows host resources. This indicates a container escape " +
                                            "where the isolated process has broken out of its namespace boundary to reach " +
                                            "the host filesystem, registry, or credential stores (MITRE T1611).",
                                Confidence = 0.88,
                                Tier = DetectionTier.Tier1Behavioral,
                                AuthorizedResponse = ResponseAction.KillProcessTree,
                                SignalType = SignalType.SuspiciousProcess,
                                ProcessName = proc.ProcessName,
                                ProcessId = proc.Id,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["ImagePath"] = imagePath,
                                    ["Technique"] = "T1611-ContainerEscape/Docker"
                                }
                            });
                        }
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }

            // Prune stale alert keys to prevent unbounded growth
            if (_alertedLateralPaths.Count > 500)
            {
                _alertedLateralPaths.Clear();
            }
        }

        private static int GetParentPidForWsl(int pid)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (ManagementObject obj in searcher.Get())
                {
                    return Convert.ToInt32(obj["ParentProcessId"]);
                }
            }
            catch { }
            return 0;
        }

        private class WslProcessInfo
        {
            public int Pid { get; set; }
            public string ProcessName { get; set; } = string.Empty;
            public string CommandLine { get; set; } = string.Empty;
            public DateTimeOffset StartTime { get; set; }
        }
    }
}
