# CyberOK Defense Tools — php2shell

Defense tooling for the PHP "php2shell" security release of 2026-10-21:

- **CVE-2026-109618** — RCE via OOM corruption ([GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w))
- **CVE-2026-109619** — RCE via stale global state ([GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp))

Affected: PHP 8.2 < 8.2.35 · 8.3 < 8.3.36 · 8.4 < 8.4.27 · 8.5 < 8.5.12.
Updating is the only complete fix; these tools help you **verify** and **detect**.

## Contents

| Component | Files | Description |
|---|---|---|
| **Safechecks** | 3 Python scripts | Behavioural vulnerability checks (local + remote + bulk scan). See [`safechecks/README.md`](safechecks/README.md) for full documentation. |
| **Suricata** | 1 rules file (20 signatures) | HTTP request/response signatures for Snort/Suricata. Validated on real exploit traffic (mod_php + FPM). |
| **ModSecurity** | 1 config file (23 rules) | WAF rules on parsed variables. Includes response-side behavioural detection and SAPI-specific crash-signal documentation. |
| **Nuclei** | 1 template | Non-destructive behavioural detection with multi-path payloads. |

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

### Suricata signatures (14)

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
| 6109 | Part flood (>500 parts) | Heap grooming |
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

### ModSecurity rules (18)

Request-side (phase 1–2): matching Suricata coverage on parsed variables +
robust occurrence counting. Response-side (phase 3/4): behavioural detection
via three-warning signature, OOM indicator, session-decode failure, and
post-exploit markers. Includes SAPI-specific crash-signal taxonomy
(mod_php vs FPM) and rejected-statuses troubleshooting guide.

## Detection notes

- **Suricata counting caveat**: occurrence counting (`{N,}`) over variable-gap
  multipart units is unreliable under PCRE2 + inspect windows — the Suricata
  set uses unit signatures; robust counting lives in ModSecurity.
- **Post-patch relevance**: rules for `PHP_SESSION_UPLOAD_PROGRESS` poisoning
  and `PHPSESSID`-as-form-field remain useful on patched versions (the
  form-SID ingestion path survives the 8.2.35 fix with `cleanup=0`).
- **Safe-checks are behavioural, not version checks**: they conclude from the
  signal itself; `php -v` remains the authoritative version answer.
- **EOL branches (5.6–8.1)**: no upstream fix exists — the safechecks verify
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

## References

- [GHSA-w8hw-w9fx-j79w / CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [GHSA-6wmf-4rv5-p3rp / CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [PHP Security Release](https://www.php.net/archive/2026.php#2026-10-21-5)

---

(c) 2026 АО «Сайбер ОК» / JSC CyberOK. Provided for informational and research
purposes only; see `LICENSE` for the full copyright and usage notice (RU + EN).
