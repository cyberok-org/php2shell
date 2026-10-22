# CyberOK Safechecks — php2shell (CVE-2026-109618 / CVE-2026-109619)

Behavioural vulnerability checks for the PHP "php2shell" security release of
2026-10-21. Each safecheck tests whether a PHP build is vulnerable or patched,
using non-destructive techniques.

## Quick start

```bash
# 109618 — single remote target (non-destructive, one POST):
python3 cyberok_safecheck_cve_2026_109618.py -u https://host/

# 109618 — bulk scan (nuclei-style targets file):
python3 cyberok_safecheck_cve_2026_109618.py -l targets.txt -t 20 -o results.json

# 109618 — custom paths:
python3 cyberok_safecheck_cve_2026_109618.py -u https://host/ --path /index.php --path /api/status

# 109618 — local decisive (needs php-cgi binary):
python3 cyberok_safecheck_cve_2026_109618.py --php-cgi /usr/bin/php-cgi

# 109619 — single remote target:
python3 cyberok_safecheck_cve_2026_109619.py -u https://host/

# 109619 — bulk scan:
python3 cyberok_safecheck_cve_2026_109619.py -l targets.txt -t 20 -o results.json

# 109619 — local decisive (needs php CLI binary):
python3 cyberok_safecheck_cve_2026_109619.py --php-cli /usr/bin/php

# Post-patch surface check (works on ALL versions, tests configuration):
python3 cyberok_safecheck_postpatch_surface.py --php-cli /usr/bin/php
```

## Modes

### Remote mode (`-u` / `--url` or `-l` / `--list`)

**Non-destructive**: sends ONE POST per target with an invalid session ID
(`Cookie: PHPSESSID=_`) and a `PHP_SESSION_UPLOAD_PROGRESS` field.

**Detection** (PortSwigger technique, credit: Tom SL): on a vulnerable build
PHP prints THREE warnings in the response; the fix removes the third.

| Warning | Vulnerable | Patched |
|---|---|---|
| "Session ID is too long or contains illegal characters" | ✓ | ✓ |
| "Failed to read session data" | ✓ | ✓ |
| "Failed to write session data (" | **✓** | **✗** |

**Verdicts**:
- `VULNERABLE` — three-warning signature present (rc=1)
- `PATCHED` — two warnings without the write attempt (rc=0)
- `MITIGATED-AT-EDGE` — 400/403/413/429 from WAF/CDN before PHP (rc=0)
- `VULNERABLE (by version)` — no crash but X-Powered-By shows unpatched (rc=1)
- `PATCHED (by version)` — X-Powered-By shows patched release (rc=0)
- `INCONCLUSIVE` — no warnings, no version (display_errors=Off?) (rc=2)

**Features**:
- `-l targets.txt` — bulk scan (one URL per line, `#` comments supported)
- `-t N` — threads (default: 10)
- `-o results.json` — structured JSON output
- `--path /custom.php` — custom paths to probe (109618 only, repeatable)
- `--timeout N` — request timeout (default: 20s)
- phpMyAdmin auto-detection: if response contains "phpMyAdmin", target is
  retested at `/show_config_errors.php` which bypasses `display_errors=Off`
  (Assetnote technique)

**Requires**: `display_errors=On` on the target for the behavioural verdict.
If Off → INCONCLUSIVE (try phpMyAdmin path or local mode).

### Local mode (`--php-cgi` / `--php-cli`)

**Decisive**: tests the PHP binary directly via throwaway subprocesses.

| Safecheck | Binary | What it tests |
|---|---|---|
| 109618 | `php-cgi` | Request-parsing OOM shapes (bailout vs soft-OOM differential) |
| 109619 | `php` (CLI) | Pre-RINIT `unserialize_callback_func` invocation gap |
| postpatch | `php` (CLI) | Form-SID ingestion + progress-key persistence + handler mismatch |

**Advantages**: works regardless of `display_errors`, WAF/CDN, or network
configuration. Gives a definitive answer about the binary.

**Disadvantages**: needs local access to the PHP binary.

### Post-patch surface check (`--php-cli`)

**NOT a CVE test** — tests whether your PHP *configuration* remains exposed
to the session-poisoning surface that survives the CVE fix. Works on ALL
versions (patched or not).

Tests:
1. Form-SID ingestion (multipart field `PHPSESSID` sets session id)
2. Progress-key persistence (`cleanup=0` vs `cleanup=1`)
3. Handler mismatch (php_serialize data read by php handler)

Mitigation: `session.upload_progress.enabled = 0`

## Exit codes

| Code | Meaning |
|---|---|
| 0 | SAFE / PATCHED / MITIGATED |
| 1 | VULNERABLE / AFFECTED / SURFACE EXPOSED |
| 2 | INCONCLUSIVE |

With bulk mode: returns 1 if ANY target is vulnerable, else 0.

## JSON output format

```json
{
  "scanned_at": "2026-10-22T09:30:00+00:00",
  "total": 5,
  "vulnerable": 2,
  "patched": 2,
  "inconclusive": 1,
  "results": [
    {
      "url": "https://target1/",
      "verdict": "VULNERABLE",
      "exit_code": 1,
      "reason": "three-warning signature: unpatched PHP attempted session write after start-up failure",
      "status": 200,
      "powered_by": "PHP/8.2.34"
    }
  ]
}
```

## Coverage matrix

| Safecheck | CVE-2026-109618 | CVE-2026-109619 | Post-patch surface |
|---|---|---|---|
| 109618 local | ✓ (OOM shapes) | — | — |
| 109618 remote | ✓ (3-warning) | ✓ (same probe) | — |
| 109619 local | — | ✓ (callback gap) | — |
| 109619 remote | ✓ (3-warning) | ✓ (same probe) | — |
| postpatch | — | — | ✓ (config check) |
