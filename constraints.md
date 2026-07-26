# Sentinel — Constraints

**Version: 1.6.2**

---

## Hard Rules â€” Never Violate

| Constraint | Rationale |
|-----------|-----------|
| No kernel drivers | Keeps the tool transparent, safe, and installable without admin trust |
| No direct syscalls | Maintains standard Windows API contract; no bypass of security boundaries |
| No persistence mechanisms | The tool must not survive reboots unless the user explicitly installs it as a service |
| No self-hiding behavior | Must be visible in process list, task manager, and event logs |
| No string-built JSON | All JSON output via `System.Text.Json` serialization only â€” no concatenation |
| No `Thread.Sleep` without cancellation | All waits must respect `CancellationToken` |
| No static mutable state | All shared state via `ConcurrentDictionary`, `Channel<T>`, or `SemaphoreSlim` |
| No shelling out to system tools | No `Process.Start("cmd.exe", ...)` for detection or response logic |
| Tier2 can never trigger action | Enforced unconditionally in `AdvancedResponseEngine.HandleAsync` â€” no exceptions, no config override |
| Active response on by default | Ships in killing mode. President's Law rules fire immediately. |
| All file reads use `FileShare.Delete` | All file I/O opens with `FileShare.ReadWrite | FileShare.Delete` — Sentinel never blocks user file deletion, even during active scanning or hashing. Only exception: intentional DLL lock files from response actions. |
| Monitors registered in groups | All background monitors must be registered via `MonitorGroup` with appropriate priority, start delay, and restart policy — no flat `AddHostedService` for monitors. |
| Monitor source files match groups | Each monitor class lives in the group file it belongs to under `Monitors/` (CriticalMonitors.cs, CoreDetectionMonitors.cs, etc.). No monolith files — new monitors go into their group file. |
| No user-session response mode toggle | The Agent MUST NOT expose any mechanism (menu item, API, named pipe, etc.) to disable ActiveResponse from user-level context. Only the Service (SYSTEM) controls response mode. |
| No async/await on STA thread | The Agent's WinForms STA message pump MUST NOT have async continuations posted to its SynchronizationContext. All background work (log tailing, file I/O, network) MUST run on dedicated `Thread` instances or `Task.Run` with `ConfigureAwait(false)`. Violations freeze the tray icon. |
| No Win32 notification API calls | `ShowBalloonTip` and toast notification APIs MUST NOT be called — `WpnService` is removed by hardening. These calls silently deadlock the STA pump without throwing. |
| Critical group: no heavy I/O at startup | Monitors in the Critical group (0ms start delay) MUST NOT perform registry enumeration, subprocess spawning, or disk-wide scanning in their constructor or early `ExecuteAsync`. Heavy-I/O monitors belong in SystemIntegrity (10s delay) or later groups. |
| Absence ≠ safety in reputation | Hash reputation services MUST return `Unknown` (not `Safe`) when a hash is absent from all databases. Only a positive trust signal (e.g., CIRCL trust > 60) can confirm Safe. |
| No string interpolation into shell commands | All PowerShell/cmd invocations MUST use `-EncodedCommand` or `ArgumentList` — never string-interpolate untrusted data into `-Command` strings. |
| Minimum-privilege process handles | `OpenProcess` calls MUST request only the access rights actually used. Never open with `PROCESS_ALL_ACCESS` unless every right is exercised. |
| Signed threat report requests | All outbound threat intelligence reports MUST be HMAC-signed with the installation entropy key. Unsigned requests to the proxy are forbidden. |
| Validate all external process output | Data from `Process.Start` stdout (docker inspect, netsh, sc.exe, etc.) is untrusted. MUST be validated before use in subsequent commands or logic. |
| Installer preserves user config | `appsettings.json` MUST use `onlyifdoesntexist` flag — upgrades never overwrite user customizations. |

---

## Detection Integrity Constraints (v1.1.0)

| Constraint | Rationale |
|-----------|-----------|
| No placeholder/fake data in detection rules | If a hash list, IOC set, or signature database isn't real, remove it. False confidence is worse than no feature. |
| No filename-based primary detection | Process names are trivially spoofed. Filename lists are metadata enrichment only, never detection triggers. |
| No security theater features | If a feature doesn't work against an attacker who reads the source code, it must be removed or honestly documented as limited. |
| Behavioral signals only for kill authority | President's Law rules must detect what processes DO (API calls, file operations, network behavior), not what they ARE (name, path, hash). |
| Hash reputation via live API only | Static hash lists in source code are immediately visible to attackers and impossible to keep current. Use HashReputationService (3-API lookup) instead. |

---

## Transparency Requirements

- Must not hide itself from the process list, task manager, or ETW
- Must not self-replicate or copy itself to other locations
- Must be fully user-controlled â€” no autonomous behavior beyond what is configured
- All actions taken (including process kills) must be logged before execution

---

## Code Quality Constraints

- **Dependency Injection** required for all services â€” no service locator, no `new` for injected dependencies
- **CancellationToken** must be threaded through every async method
- **All disposable objects** must implement `IAsyncDisposable` and be disposed in `StopAsync` / `DisposeAsync`
- **No silent exception swallowing** â€” every `catch` block must log the exception (debug level minimum)
- **Graceful degradation** â€” if a monitor fails to start, log the error and continue; do not crash the host

---

## Testing Constraints

- Every Tier1 rule must have at least one test that verifies it fires and returns `Tier1Behavioral`
- Every Tier2 rule must have at least one test that verifies it returns `Tier2Indicator`
- The `ResponseEngine` Tier2 contract must be verified by automated test: Tier2 detection with `activeResponseEnabled: true` must still produce `LogOnly`
- Composite detection rules must be testable with a mock `IDetectionEngine` (no live system access)
- Tests must not require elevation, network access, or specific file system state

---

## Deception Constraints (v1.7.0)

| Constraint | Rationale |
|-----------|-----------|
| Deception time budget: 2 seconds maximum | Kill must never be significantly delayed by deception. Attacker is still active during deception window. |
| Deception failure never prevents kill | Deception is a bonus, not a gate. All tactic failures are caught and logged; kill proceeds unconditionally. |
| Never deceive own PID or PID â‰¤ 4 | Self-protection and system stability. Deception targets only confirmed malicious processes. |
| No deception on Tier2 detections | Deception only fires on President's Law kills. Tier2 is log-only â€” no action of any kind. |
| Beacon flooding only targets public IPs | Never flood private/loopback addresses. Prevents accidental DoS of local services. |
| All deception actions logged before execution | Full forensic trail. User can review exactly what was done and revert if needed. |
| Environment poisoning is HKCU-scoped only | Never modify HKLM (system-wide). Limits blast radius to the compromised user session. |
| Honeypot files use non-standard names (.bak, backup) | Prevents confusion with real credentials. Legitimate applications won't read these files. |
| Sparse files and symlinks are deployed in hidden/cache directories | Minimizes user-visible filesystem clutter. |
| Ransomware bypasses deception | Ransomware kills proceed instantly without running deception tactics to minimize file encryption damage. |
| Thread suspension for context queries | Thread context queries on x64 must suspend target threads to avoid random access violations or stack corruption. |
| Async execution for network/off-host deception | Network-based deception (BeaconFlooder, NetworkHoneypotDeployer) must run asynchronously in the background so they do not block process termination or exhaust the pre-kill budget. |

---

## Operational Constraints

- Must run on Windows 10 / Windows Server 2019 or later
- Must target `net10.0-windows`
- Must function as a standard user (reduced capability, no crash)
- Must function as an elevated user (full capability)
- Log files must not grow unbounded â€” rotation required (50 MB / 5 files)
- Detection deduplication required â€” same signal must not flood the log


