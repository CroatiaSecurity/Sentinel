# v1.3.3 — Context Bus + Cross-Monitor Intelligence

Sentinel is no longer a collection of independent detections. Monitors now share intelligence in real-time through a unified Context Bus, and all responses are serialized through a Response Coordinator that prevents races and duplicates.

## What's New

### Context Bus (Cross-Monitor Enrichment)
- Thread-safe pub/sub with bounded channels (10K capacity, backpressure-aware)
- Per-PID signal cache for synchronous queries (monitors can ask "what do we know about PID X?")
- 9 typed enrichment signals flow between monitors:
  - `NetworkC2Signal`, `GhostProcessSignal`, `DnsAnomalySignal`, `FileVerdictSignal`
  - `InjectionSignal`, `EphemeralProcessSignal`, `ExfiltrationSpikeSignal`
  - `CredentialAccessSignal`, `NetworkPolicyViolationSignal`
- TTL-based expiry, drop rate alerting, LRU cache eviction

### Response Coordinator
- Per-PID semaphore locking (one response action per process at a time)
- 30-second deduplication window (5 detections on same PID = 1 kill, not 5)
- ChainTracer hold system (don't kill a process while tracing its parent chain)
- Response escalation (stronger action overrides weaker within dedup window)
- Full audit trail of every response decision (executed, deduplicated, deferred, failed)

### Pipeline Backpressure Monitoring
- Orchestrator health check every 10s
- Alerts when ContextBus signal drop rate exceeds 5%
- Auto-prunes expired cache and stale response state
- SystemHealthStatus now includes ContextBus + ResponseCoordinator metrics

### Cross-Monitor Intelligence (examples)
- BeaconingDetector confirms C2 → GhostProcessMonitor immediately validates ghost PIDs against it
- GhostProcessMonitor finds orphan → BeaconingDetector flags it for priority beaconing analysis
- DnsQueryMonitor detects DGA → GhostProcessMonitor correlates ghost connections with DGA domains
- FileReputationEngine scores a binary → AppNetworkPolicyMonitor adjusts alert severity

## Architecture

```
Monitor → TelemetryFusion → DetectionEngine → Orchestrator → ResponseCoordinator → ResponseEngine
                                                    ↓                    ↓
                                            IncidentManager        ContextBus
                                            (group, escalate)   (cross-enrichment)
```

Every detection is grouped into an incident, every response is coordinated, and every monitor shares what it knows with every other monitor that needs it.
