## What's New

### Application Integrity Monitor (Cuckoo Egg Detection)

Detects and responds to unauthorized replacement of protected applications. Prevents someone from swapping your legitimate software (e.g., Kiro IDE) with an impostor (e.g., Cursor).

**Detection:**
- Baselines protected executables at startup (SHA-256 + Authenticode publisher)
- Real-time FileSystemWatcher + 30s periodic integrity scan
- Distinguishes legitimate updates (same publisher) from attacks (different/missing publisher)

**Response:**
- Kills the offending installer/process tree
- Quarantines the impostor binary (DPAPI-encrypted vault)
- Restores the original application from backup

**Forensic Reporting:**
- Generates a full incident report suitable for filing with law enforcement
- Includes: process ancestry, network connections, Authenticode certificates, timeline, legal classification

**Configuration:**

Add protected apps to `appsettings.json` under the `ApplicationIntegrity` section.

**Full Changelog**: https://github.com/CroatiaSecurity/Sentinel/compare/v1.2.5...v1.2.6
