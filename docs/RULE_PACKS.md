# Sentinel Rule Packs (v2.0)

Signed correlation rule packs extend multi-signal detection **without recompiling** Sentinel.

## Location

| Path | Purpose |
|------|---------|
| `%ProgramData%\Sentinel\rules\packs\*.pack.json` | Runtime packs (preferred) |
| `{installDir}\rules\packs\*.pack.json` | Bundled packs |

## Format

```json
{
  "name": "example-terminal",
  "version": "1.0",
  "rules": [
    {
      "name": "Credential + Beacon",
      "minSignals": 2,
      "requiredFragments": ["LSASS", "Beacon"],
      "confidence": 0.93,
      "evidence": "Credential access with C2-like network",
      "reasoning": "Two independent fragments on one PID within the correlation window.",
      "attackTechniques": ["T1003.001", "T1071"]
    }
  ],
  "hmac": "<hex HMAC-SHA256>"
}
```

## Signing

HMAC key = `HMAC-SHA256(install_entropy, "sentinel-rule-pack-signing-v1")`  
where `install_entropy` is the 32-byte file at `%ProgramData%\Sentinel\Secure\.install_entropy` (SYSTEM-only).

Sign the JSON **with the `hmac` field removed**. Fail-closed: packs without a valid signature never load.

PowerShell (run as SYSTEM / with entropy read access):

```powershell
# Conceptual — production signing should run under SYSTEM context
$entropy = [IO.File]::ReadAllBytes("$env:ProgramData\Sentinel\Secure\.install_entropy")
$hmacKey = [Security.Cryptography.HMACSHA256]::new($entropy).ComputeHash(
  [Text.Encoding]::UTF8.GetBytes("sentinel-rule-pack-signing-v1"))
# Remove hmac field from JSON, then:
$payload = [Text.Encoding]::UTF8.GetBytes($jsonWithoutHmac)
$sig = [BitConverter]::ToString(
  [Security.Cryptography.HMACSHA256]::new($hmacKey).ComputeHash($payload)
).Replace("-","").ToLowerInvariant()
```

## Semantics

- Each rule becomes an `ICorrelationRule` (`FragmentCorrelationRule`).
- All `requiredFragments` must appear (case-insensitive substring) in **distinct** rule names already buffered for the same PID.
- Match emits a chain-confirmed composite: `Rule Pack: {name}`.
- Still subject to `ObserveUntilChain` / `ResponsePolicy` / product posture.

## Security notes

- Only SYSTEM can read install entropy → only SYSTEM can forge packs.
- Administrators with file write but without entropy cannot inject kill rules.
- Packs never disable ActiveResponse or product posture.
