# CyberOK Defense Tools — php2shell

Defense tooling for the PHP "php2shell" security release of 2026-10-21:

- **CVE-2026-109618** — RCE via OOM corruption ([GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w))
- **CVE-2026-109619** — RCE via stale global state ([GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp))

Affected: PHP 8.2 < 8.2.35 · 8.3 < 8.3.36 · 8.4 < 8.4.27 · 8.5 < 8.5.12.
Updating is the only complete fix; these tools help you **verify** and **detect**.

## Contents

| File | What it is |
|---|---|
| `safechecks/cyberok_safecheck_cve_2026_109618.py` | Behavioural safe-check for CVE-2026-109618: drives a throwaway `php-cgi` with the official request-parsing OOM shapes and returns a verdict (pre-fix bailout window vs patched soft-OOM). Validated: 8.2.34 → AFFECTED (rc 1), 8.2.35 → SAFE (rc 0). |
| `safechecks/cyberok_safecheck_cve_2026_109619.py` | Behavioural safe-check for CVE-2026-109619: poisoned session record + one multipart POST against a throwaway single-worker `php -S`; detects the pre-RINIT `unserialize_callback_func` invocation (the user-code gap the fix closes). Validated: 8.2.34 → VULNERABLE (rc 1), 8.2.35 → SAFE (rc 0). |
| `suricata/cyberok_php_up_2026.rules` | 8 Suricata (Snort3-adaptable) signatures: chunked-multipart bypass, part-header amplification, deeply nested names, empty file controls, upload-progress poisoning (serialized payload / PHP tag in value and filename), PHPSESSID-as-form-field. Validated on replayed real trigger traffic: 7/7 fire, clean control silent. |
| `modsecurity/cyberok_php_up_2026.conf` | ModSecurity v2/v3 companion: the same surfaces on parsed variables (`ARGS`, `FILES_NAMES`, `ARGS_NAMES`) plus robust occurrence counting for the empty-filename flood (kept in the WAF layer — see notes). Desk-verified; burn in `DetectionOnly` before blocking. |
| `LICENSE` | Copyright and usage notice (RU + EN). |

## Usage

```bash
# Local, decisive (run on the origin host; touches only throwaway processes):
python3 safechecks/cyberok_safecheck_cve_2026_109618.py --php-cgi /usr/bin/php-cgi
python3 safechecks/cyberok_safecheck_cve_2026_109619.py --php-cli /usr/bin/php

# Remote surface mode (109618 safe-check only — reachability, not a version verdict):
python3 safechecks/cyberok_safecheck_cve_2026_109618.py --url https://host/

# Suricata: include the rules file, then check alerts:
include: cyberok_php_up_2026.rules
# offline replay of a capture:
suricata -c suricata.yaml -S cyberok_php_up_2026.rules -k none -r capture.pcap -l out/

# ModSecurity: include into your vhost/global config after SecRequestBodyAccess On
```

## Detection notes

- **Deployment variables**: adjust `$HTTP_PORTS` / `HOME_NET`; offline analysis of
  loopback captures needs `-k none` (checksum offload).
- **Counting caveat (Suricata)**: occurrence counting (`{N,}`) over variable-gap
  multipart units is unreliable under Suricata's PCRE2 + inspect windows — the
  Suricata set uses the high-specificity *unit signature* for the empty-file
  flood; robust `{50,}` counting lives in the ModSecurity companion.
- **Post-patch relevance**: rules for `PHP_SESSION_UPLOAD_PROGRESS` poisoning and
  `PHPSESSID`-as-form-field remain useful **on patched versions**: the form-SID
  ingestion path survives the 8.2.35 fix (with `session.upload_progress.cleanup=0`
  the progress data still lands in the attacker-chosen session file), so these
  stay enabled as poisoning-enabler signals. Session-id traversal via this path
  is closed by the `[A-Za-z0-9,-]` charset validator on both versions.
- **Safe-checks are behavioural, not version checks**: they conclude from the
  signal itself (startup-phase bailout / pre-RINIT callback invocation); `php -v`
  on the origin remains the authoritative version answer.

## Validation summary (2026-10-21)

- Safe-checks: A/B-validated on ASan debug builds of PHP 8.2.34 (vulnerable) and
  8.2.35 (patched) plus a stock `php:8.2.34-apache` mod_php stand; differentials
  confirmed on 5/5 repeated runs (109618) and deterministic single-run (109619).
- Suricata: real trigger shapes captured on a live stand, replayed through the
  rules — 7/7 trigger signatures fired, the clean upload control raised nothing.

## References

- GHSA-w8hw-w9fx-j79w / CVE-2026-109618 — https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- GHSA-6wmf-4rv5-p3rp / CVE-2026-109619 — https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp

---

(c) 2026 АО «Сайбер ОК» / JSC CyberOK. Provided for informational and research
purposes only; see `LICENSE` for the full copyright and usage notice (RU + EN).
