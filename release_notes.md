## What's New in v1.4.0

### SentinelOrchestrator — Phase 1: Operating as a Unit

Sentinel is no longer a bag of independent monitors. It's now a coordinated EDR with centralized incident management, monitor supervision, and response coordination.

#### Incident Manager

Multiple detections on the same attack are now ONE incident:
- Grouped by PID, parent process chain, or file hash (reinfection detection)
- Lifecycle: Open → Active → Responded → Closed
- Severity escalation: Low → Medium → High → Critical based on corroborating signals
- Logged as `incident_created` / `incident_closed` events for analyst review

#### Monitor Registry & Watchdog

Every monitor is now supervised:
- Heartbeat tracking with 60s stale warning, 3m critical timeout
- Automatic restart of crashed monitors (up to 5 attempts)
- Anti-tamper detection fires when monitors die unexpectedly
- Real-time dashboard of all monitor states

#### Startup Sequencer

Dependency-ordered boot:
- Phase 1: Infrastructure (logging, cache, crypto)
- Phase 2: Engines (detection, response, reputation)
- Phase 3: Monitors (all 40+ detection monitors)
- Phase 4: Validators (self-test, health check)
- Per-component timeout enforcement
- Startup report with timing for every component

#### Response Coordination

No more duplicate kills or race conditions:
- Per-PID response lock prevents multiple threads from killing the same process
- Orchestrator gates response engine — incidents are grouped first, then responded
- ChainTracer can safely walk parent chains without another thread interfering

**Full Changelog**: https://github.com/CroatiaSecurity/Sentinel/compare/v1.3.1...v1.4.0
