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
PHP emits a session write-after-failure warning in the response; the fix
removes the write attempt.

| Warning | Vulnerable | Patched |
|---|---|---|
| w1 "session id is too long or contains illegal characters" (case-insensitive; text is "The session id…" on 7.x/5.6) | ✓ | ✓ |
| w2 "Failed to read session data" | ✓ (never fires on 5.6) | ✓ |
| w3 "Failed to write session data (" | **✓ (decisive)** | **✗** |

**Verdicts**:
- `VULNERABLE` — w1 + w3 signature present (rc=1)
- `PATCHED` — w1 + w2 without the write attempt (rc=0)
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

**Requires**: error display enabled on the target for the behavioural verdict:
- PHP ≥ 8.0: `display_errors=On` is enough.
- PHP ≤ 7.4 / 5.6: these are RINIT-time warnings and reach the response
  **only with `display_startup_errors=On`** (common on dev/staging and
  misconfigured production). With it Off the response is byte-identical to
  a benign request and no behavioural verdict is possible.
- A valid `session.save_path` does NOT suppress w3 — the write is refused
  because of the failed session state, not the path (verified on 8.1.34
  with `save_path=/tmp`).

If warnings are unavailable → INCONCLUSIVE (try phpMyAdmin path, version
fallback, or local mode).

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

### EOL branches (PHP 5.6 – 8.1): source backports available

The PHP security team published source backport patches for 7.4, 8.0, 8.1.
These branches are NOT automatically "always vulnerable" — verify your
distribution's backport status. Note: the 8.1 backport fixes both CVEs
without adding `memory_hard_limit_percent`, so absence of that directive
does NOT prove vulnerability.

Official fixes exist only for supported branches (8.2.35 / 8.3.36 / 8.4.27 /
8.5.12+). EOL branches will never receive an upstream fix, so for them the
behavioural check confirms "the vulnerable behaviour is live", not
"patched vs unpatched" — there is no patched EOL state to distinguish.
Verified vulnerable by direct testing: 5.6.40, 7.0.33, 7.2.34, 7.3.33,
7.4.33, 8.0.30, 8.1.34 (109619 local fires on all of them; the remote
signature works with `display_startup_errors=On`).

**Do not read silence on an EOL target as "clean".** If the behavioural
probe is INCONCLUSIVE and `X-Powered-By` shows an EOL version, treat the
target as vulnerable-by-version.

### Why INCONCLUSIVE on hardened production is by design

With `display_errors=Off` + `display_startup_errors=Off` (correctly
configured production) the response carries **no** patch-correlated signal.
We hunted for alternative remote oracles on live unpatched (8.1.34) vs
patched (8.2.35) builds:

- **Headers / status / body**: byte-identical across all probe variants
  (illegal SID ± upload progress, with and without an app-level
  `session_start()`). The fix changes only internal behaviour — nothing
  leaks into the HTTP response.
- **Session-cookie behaviour**: identical (Set-Cookie, Expires,
  Cache-Control all match).
- **Timing oracle (109618 mpheaders shape)**: exists but is weak.
  A ~190k-header multipart form takes ~41 ms over baseline on unpatched
  vs ~17 ms on patched locally (early parser bailout), with clean
  separation — but the ~20–25 ms absolute delta drowns in WAN jitter,
  requires per-target baselining (heavy form minus benign form, median of
  N≥30), and is capped by the target's `post_max_size`. Experimental
  statistical signal at best, not a single-request verdict.

So on hardened production: warning-signature if errors are displayed →
statistical timing (fragile) → version fallback → local decisive mode.
An INCONCLUSIVE here is an honest answer, not a tool deficiency.

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
