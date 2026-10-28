# CyberOK Defense Tools — php2shell

Defense tooling for the PHP "php2shell" security release of 2026-10-21:

- **CVE-2026-109618** — RCE via OOM corruption ([GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w))
- **CVE-2026-109619** — RCE via stale global state ([GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp))

Affected: PHP 8.2 < 8.2.35 · 8.3 < 8.3.36 · 8.4 < 8.4.27 · 8.5 < 8.5.12.
Updating is the only complete fix; these tools help you **verify** and **detect**.

**EOL branches (7.4, 8.0, 8.1)**: the PHP security team published source
backports — these branches are not automatically "always vulnerable".
Verify your distribution's backport status; `memory_hard_limit_percent`
absence does NOT prove vulnerability (the 8.1 backport fixes both CVEs
without adding that directive).

## Contents

| Component | Files | Description |
|---|---|---|
| **Safechecks** | 4 Python scripts | Behavioural vulnerability and configuration checks (local + remote + bulk scan). See [`safechecks/README.md`](safechecks/README.md) for full documentation. |
| **Suricata** | 1 rules file (21 signatures) | HTTP request/response signatures for Snort/Suricata. Validated on real exploit traffic (mod_php + FPM). |
| **ModSecurity** | 1 config file (21 rules) | WAF rules on parsed variables. Includes response-side behavioural detection and SAPI-specific crash-signal documentation. |
| **Nuclei** | 4 templates (behavioural + surface + EOL + startup-surface) |
| **Sigma** | 4 SIEM rules (HTTP exploit, PHP OOM, session decode, process creation) | Non-destructive behavioural detection with multi-path payloads. |
| **Host hunt** | 7 YARA rules, dated IOC manifest, Python runner and 25 regression tests | Read-only filesystem triage of webroots, PHP session files, temporary artifacts and decoded request captures. See [`host-hunt/README.md`](host-hunt/README.md) / [Русский](host-hunt/README.ru.md). |

## Quick start

### Scan your infrastructure

```bash
# Single target:
python3 safechecks/cyberok_safecheck_cve_2026_109618.py -u https://host/

# Bulk scan (nuclei-style targets file + threads + JSON):
python3 safechecks/cyberok_safecheck_cve_2026_109618.py -l targets.txt -t 20 -o results.json

# Custom paths:
python3 safechecks/cyberok_safecheck_cve_2026_109618.py -u https://host/ --path /index.php --path /api/status

# CVE-2026-109619 — same interface:
python3 safechecks/cyberok_safecheck_cve_2026_109619.py -u https://host/
python3 safechecks/cyberok_safecheck_cve_2026_109619.py -l targets.txt -t 20 -o results.json
```

### Check a specific PHP binary (decisive)

```bash
python3 safechecks/cyberok_safecheck_cve_2026_109618.py --php-cgi /usr/bin/php-cgi
python3 safechecks/cyberok_safecheck_cve_2026_109619.py --php-cli /usr/bin/php
```

### Check post-patch configuration exposure

```bash
python3 safechecks/cyberok_safecheck_postpatch_surface.py --php-cli /usr/bin/php
```

### Deploy detection rules

```bash
# Suricata:
include: suricata/cyberok_php_up_2026.rules
# offline replay:
suricata -c suricata.yaml -S suricata/cyberok_php_up_2026.rules -k none -r capture.pcap -l out/

# ModSecurity:
Include modsecurity/cyberok_php_up_2026.conf

# Nuclei:
nuclei -t nuclei/cyberok_php2shell_detect.yaml -u https://target/
```

## Detection coverage

### Suricata signatures (21)

| SID | Detection | Vector |
|---|---|---|
| 6101 | Chunked multipart POST | 109618-A (post_max_size bypass) |
| 6102 | Part-header amplification (100+) | 109618-B |
| 6103 | Generic header-run amplification | 109618-B (variant) |
| 6104 | Deeply nested input names (40+) | 109618 aux |
| 6105 | Empty-filename file control | 109618-C |
| 6106 | Serialized payload in UPLOAD_PROGRESS | 109619 (poisoning) |
| 6107 | Payload in multipart filename | 109619 (carrier) |
| 6108 | PHPSESSID as form field | 109619 (sid injection) |
| 6109 | 10+ consecutive Content-Disposition headers | Header-run anomaly; not a total multipart-part counter |
| 6110 | Handler-mismatch seed (pipe+serialized) | 109619 (handler mismatch) |
| 6111 | Set-Cookie PHPSESSID leak oracle | 109618 (response-side) |
| 6112 | Giant multipart filename (>4000 chars) | 109618 arm |
| 6113 | UPLOAD_PROGRESS field present (anomaly) | Generic |
| 6114 | Invalid PHPSESSID cookie (charset) | Generic |
| 6115 | Session-file path in URI (LFI trigger) | 109619 (include/LFI sink) |
| 6116 | OOM in response body | 109618 (response-side, vulnerable only) |
| 6117 | Session destruction failed in response | 109619 (response-side, vulnerable only) |
| 6118 | Failed to decode session object | 109619 (response-side) |
| 6119 | Post-exploit webshell access (p2s_*) | Post-exploit IoC |
| 6120 | Post-exploit marker (SHELL_ALIVE) | Post-exploit IoC |
| 6121 | Serialized integer-key collision sequence | Captured exploit request pattern (Corelight-derived) |

### ModSecurity rules (21)

Request-side (phase 1–2): matching Suricata coverage on parsed variables +
robust occurrence counting. Response-side (phase 3/4): behavioural detection
via three-warning signature, OOM indicator, session-decode failure, and
post-exploit markers. Includes SAPI-specific crash-signal taxonomy
(mod_php vs FPM) and rejected-statuses troubleshooting guide.

### Host hunt

Use filesystem evidence alongside the existing event-based Sigma rules. The
host-hunt rules distinguish exact known malware sample hashes, public PoC
content, suspicious session data and generic PHP execution patterns. A match
requires investigation; it does not automatically prove execution or attribute
initial access to these CVEs. Each IOC records its source and role.

From the repository root, using actual paths from the PHP instance or a mounted
snapshot:

```bash
python3 -m venv host-hunt/.venv
host-hunt/.venv/bin/python -m pip install -r host-hunt/requirements.txt
host-hunt/.venv/bin/python host-hunt/hosthunt.py \
  --webroot /mnt/server/var/www/html \
  --session-dir /mnt/server/var/lib/php/sessions \
  --artifact-dir /mnt/server/tmp \
  > host-hunt/findings.jsonl

# Offline regression tests; no PHP or malware is executed:
host-hunt/.venv/bin/python -m unittest discover -s host-hunt -p 'test_*.py' -v
```

The runner outputs paths, hashes and rule metadata without session contents.
Exit `1` means findings (also inspect `incomplete`); `2` means incomplete without
findings; `0` means no match in the scanned scope. Unreadable, oversized,
changing, archived and symlinked files are reported as skipped. Filesystem
scanning does not cover process memory, deleted artifacts or Redis/Memcached
session stores. See the [host-hunt guide](host-hunt/README.md) for scope, limits
and log-search examples.

## Detection notes

- **Sigma telemetry**: the HTTP rule needs `http_request_body`; standard nginx
  combined access logs do not contain request bodies or cookies. Process rules
  require process-creation telemetry and backend field mapping. YARA supplies
  complementary disk evidence, not missing historical events.
- **PoC provenance**: `p2s_8512_shell.php` and `SHELL_ALIVE` belong to different
  public PoCs. Host-hunt detects them separately. Authorized checks and research
  fixtures may match; known test markers are reported, never automatically
  suppressed. A negative scan does not establish that a host was uncompromised.
- **Suricata counting caveat**: occurrence counting (`{N,}`) over variable-gap
  multipart units is unreliable under PCRE2 + inspect windows — the Suricata
  set uses unit signatures; robust counting lives in ModSecurity.
- **Post-patch relevance**: rules for `PHP_SESSION_UPLOAD_PROGRESS` poisoning
  and `PHPSESSID`-as-form-field remain useful on patched versions (the
  form-SID ingestion path survives the 8.2.35 fix with `cleanup=0`).
- **Safe-checks are behavioural, not version checks**: they conclude from the
  signal itself; `php -v` remains the authoritative version answer.
- **EOL branches (5.6–8.1)**: source backports exist (php.net) — verify your distro
  the vulnerable *behaviour* on them (all confirmed vulnerable by direct
  testing). Remote detection on ≤7.4 requires `display_startup_errors=On`
  on the target; on hardened production (both display flags Off) no
  patch-correlated signal reaches the HTTP response at all — headers, body
  and cookie behaviour are byte-identical between unpatched and patched
  builds, so INCONCLUSIVE there is by design (see `safechecks/README.md`
  for the oracle hunt, incl. the fragile timing differential).

## Validation summary

| Test | Result |
|---|---|
| Safechecks local (8.2.34 vs 8.2.35 ASan) | Both decisive (A/B) |
| Safechecks remote (php:8.2.34-apache vs php:8.2.35-fpm) | Both decisive |
| Bulk scan (2 targets, JSON) | Correct: 1 vulnerable + 1 patched |
| Suricata vs mod_php traffic | 9/10 request signatures fired, control silent |
| Suricata vs FPM traffic | 9/10 fired, control silent |
| Suricata new rules on FPM (6115-6120) | 4/6 fired (LFI, webshell IoC, 8512-seed, anomaly); 2 response-side need vulnerable build |
| ModSecurity patterns | Desk-verified against exact trigger bytes |
| phpMyAdmin retest | Technique validated (Assetnote) |
| ikow rules comparison | 10/12 covered by our set; 2 gaps (threshold-recon, version-inventory) noted |
| Host-hunt YARA | 7 rules compile without warnings in yara-python 4.5.4 |
| Host-hunt regression tests | 25/25 offline tests passed; synthetic positives/negatives and runner coverage/error semantics. No real-malware execution or clean-application FP corpus. |

## References

- [GHSA-w8hw-w9fx-j79w / CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [GHSA-6wmf-4rv5-p3rp / CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [PHP Security Release](https://www.php.net/archive/2026.php#2026-10-21-5)

---

(c) 2026 АО «Сайбер ОК» / JSC CyberOK. Provided for informational and research
purposes only; see `LICENSE` for the full copyright and usage notice (RU + EN).
