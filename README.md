# CyberOK Defense Tools — php2shell

Defense tooling for the PHP "php2shell" security releases:

- **Wave 1 — 2026-10-21** (below): safechecks, Suricata, ModSecurity, nuclei, Sigma, host hunt.
- **Wave 2 — 2026-11-19** (8.2.36 / 8.3.37 / 8.4.28 / 8.5.13, 17 GHSAs): Suricata, ModSecurity
  and host-hunt scanners — see [Wave 2](#wave-2--2026-11-19-release). Wave-2 safechecks and
  nuclei templates are not published here.

Wave 1 — the 2026-10-21 release:

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
| **Suricata** | 2 rules files: `cyberok_php_up_2026.rules` (25 signatures: 21 wave-1 + 4 wave-2) and `cyberok_php_up_2026_w2.rules` (46 wave-2 signatures) | HTTP request/response signatures for Suricata 7. Validated on real exploit traffic (mod_php + FPM; wave 2: nginx/Apache/HAProxy → FPM, php-cgi, SOAP). No SID overlap — load both. |
| **ModSecurity** | 2 config files: `cyberok_php_up_2026.conf` (24 rules: 21 wave-1 + 3 wave-2) and `cyberok_php_up_2026_w2.conf` (35 wave-2 rules) | WAF rules on parsed variables. Includes response-side behavioural detection and SAPI-specific crash-signal documentation. Load-tested on ModSecurity v3 + CRS 4. |
| **Nuclei** | 4 templates (behavioural + surface + EOL + startup-surface) |
| **Sigma** | 4 SIEM rules (HTTP exploit, PHP OOM, session decode, process creation) | Non-destructive behavioural detection with multi-path payloads. |
| **Host hunt** | Wave 1: 7 YARA rules, dated IOC manifest, Python runner and 25 regression tests. Wave 2: 4 stdlib scanners (session store, logs, code/config, phar `.pubkey`) and 11 regression tests | Read-only filesystem triage of webroots, PHP session files, logs, code, phar archives, temporary artifacts and decoded request captures. See [`host-hunt/README.md`](host-hunt/README.md) / [Русский](host-hunt/README.ru.md). |

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
# Suricata (wave 1 + wave 2):
rule-files:
  - cyberok_php_up_2026.rules
  - cyberok_php_up_2026_w2.rules
# offline replay:
suricata -c suricata.yaml -S suricata/cyberok_php_up_2026.rules -k none -r capture.pcap -l out/

# ModSecurity (wave 1 + wave 2):
Include modsecurity/cyberok_php_up_2026.conf
Include modsecurity/cyberok_php_up_2026_w2.conf

# Nuclei:
nuclei -t nuclei/cyberok_php2shell_detect.yaml -u https://target/
```

## Detection coverage

### Suricata signatures — `cyberok_php_up_2026.rules` (21 wave-1 + 4 wave-2)

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
| 6130 | FastCGI BEGIN_REQUEST record inside an HTTP request body | Wave 2: CVE-2026-129289 (FPM smuggling) |
| 6131 | `.php` URI with a 512+ byte suffix | Wave 2: CVE-2026-129538 (php-cgi PATH_INFO) |
| 6132 | Dense obs-fold continuation cluster in a response (raw stream) | Wave 2: CVE-2026-127960 (PHP as HTTP client) |
| 6133 | Newline in the `.php` URI suffix | Wave 2: CVE-2026-129538 (split locations without `try_files`) |

### ModSecurity rules — `cyberok_php_up_2026.conf` (21 wave-1 + 3 wave-2: 1006130–1006132)

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

## Wave 2 — 2026-11-19 release

Fixed in **8.2.36 / 8.3.37 / 8.4.28 / 8.5.13**; everything older is affected
within each advisory's range, and EOL branches get no fix (CVE-2026-129289 was
reproduced on official 7.4 and 8.1 images). Updating remains the only complete
fix. The rules and scanners below detect attempts and leftovers; they do not
prove exploitation.

| CVE · GHSA | What | Suricata SIDs | ModSecurity IDs | Host hunt |
|---|---|---|---|---|
| CVE-2026-129289 · qc49-hpvq-g2w6 | FPM request smuggling through an unread body (nginx `fastcgi_keep_conn on`, Apache `enablereuse=on`, **HAProxy `fcgi-app` by default**) | 6200–6206, 6130 | 1006200–1006206, 1006130 | — |
| CVE-2026-115560 · 658j-r8rw-q6mx | Session serializer mismatch via upload progress | 6220–6225, 6228 | 1006220–1006225 | `session_store_hunt.py`, `log_hunt.py` |
| CVE-2026-126714 · fm2m-fjf5-v3cp | Partially overwritten session file | 6223, 6224 | 1006222, 1006223 | `session_store_hunt.py`, `log_hunt.py` |
| CVE-2026-129496 · gr4f-wgx5-jpfv | tzcache use-after-free (early request diagnostics in a fresh worker) | 6240–6247 | 1006240–1006247 | — |
| CVE-2026-129538 · 5j3f-64r7-f564 | php-cgi PATH_INFO out-of-bounds read/write | 6250–6252, 6131, 6133 | 1006250, 1006131, 1006132 | — |
| CVE-2026-129292 · 3mg3-cr28-46gc | FPM status page XSS (Basic-auth user, script) | 6255–6258 | 1006255–1006258 | — |
| CVE-2026-129182 · 2fjv-p558-g82m (8.5) | Fatal backtrace repopulated during shutdown | 6226 | — | `log_hunt.py` |
| CVE-2026-129474 · 8mjj-2r7p-4hg2 (8.5) | Trampoline-args UAF in fatal backtraces | 6227 | 1006226 | `log_hunt.py` |
| CVE-2026-129481 · g3vh-838c-65v7 (8.3+) | Stale session filename after interrupted shutdown | — | — | `log_hunt.py` |
| CVE-2026-129506 · 4646-p932-gw34 | SOAP DTD entity use-after-free | 6260–6264 | 1006260–1006264, 1006267 | `php_wave2_code_hunt.py` |
| CVE-2026-15353 · q23r-hr55-xmpg | SOAP empty `arraySize` heap disclosure | 6265–6267 | 1006265, 1006266 | — |
| CVE-2026-129501 · x8r7-mg3g-74hg (8.4+) | `Dom\XMLDocument::saveXml` double free | — | — | `php_wave2_code_hunt.py` |
| CVE-2026-127960 · mmf9-xm3v-hg2x | Quadratic folded response headers (PHP as HTTP client) | 6268, 6269, 6132 | — (by design) | `php_wave2_code_hunt.py` |
| CVE-2026-128064 · f6gg-rchx-xw8j | `HTTPS://` / `FTPS://` sent in plaintext | 6270–6274 | — | `php_wave2_code_hunt.py` |
| CVE-2026-128090 · 68fq-fh7h-f8gr | Phar OpenSSL signature downgrade | — | — | `phar_pubkey_scan.py` |
| CVE-2026-129438 · mg3p-mxj9-g2mm (8.5) | `Uri\Rfc3986` around 2 GiB | — | — | `php_wave2_code_hunt.py` (info) |
| CVE-2026-129291 · jm4m-qfqx-967m | FPM master epoll UAF (local privilege escalation) | — | — | config: `catch_workers_output=yes` (set in official php-fpm images) |

### Wave-2 deployment notes

- **Load both rule files** of each engine; SID/ID spaces do not overlap.
- **`EXTERNAL_NET` must be set properly**: SID 6250 (FastCGI from an external
  client) is for the internet-facing edge; with `EXTERNAL_NET=any` it also fires
  on the internal web→FPM leg.
- **Deploy SIDs 6268 and 6269 together**: libhtp does not finish header blocks over
  1 MB, so only the raw-stream rule sees very large folded responses.
- **Inspection limits**: Suricata `request-body-limit` and ModSecurity body limits
  cap body inspection; TLS must be terminated before the sensor.
- **CRS already covers part of the surface**: 200002/200003 reject the multipart
  smuggling primitive, 200007 the >1000-variable shapes. It does not cover the
  cookie-based trigger of 129496, Basic-auth XSS (129292) or the PUT smuggling
  carrier — the wave-2 rules do.
- **`%0A` in the `.php` suffix (129538)** reaches php-cgi through split locations
  that lack a `try_files`/file-existence check (the CVE-2019-11043 technique);
  with `try_files $fastcgi_script_name =404` the lab stayed clean.

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
| Wave 2: Suricata load | 71/71 signatures (both files) load on Suricata 7.0.3, no warnings |
| Wave 2: Suricata replay | 25 lab pcaps (trigger and benign traffic from nginx/Apache/HAProxy → FPM, php-cgi, SOAP): trigger traffic fires the corresponding rules (except the Apache `Action` + rewrite PATH_INFO request of 129538, which is an ordinary GET with no network signature); on a 15-flow benign corpus (binary uploads, SOAP, JSON, Basic auth, upload progress) the wave-2 rules give 0 alerts (the wave-1 anomaly rule 6113 fires on the legitimate upload-progress form, as documented; 6206 is a context rule that also fires on same-shape probes) |
| Wave 2: ModSecurity | Both files load together with CRS 4.30 on libmodsecurity 3.0.17 (a deliberately broken file crashes the same harness); triggers fire their IDs, benign requests none |
| Wave 2: host-hunt tests | 11/11 offline tests for the code hunt and phar scanner |

## References

- [GHSA-w8hw-w9fx-j79w / CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [GHSA-6wmf-4rv5-p3rp / CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [PHP Security Release](https://www.php.net/archive/2026.php#2026-10-21-5)
- Wave 2: [PHP 8.5.13 / 8.4.28 / 8.3.37 / 8.2.36 release notes](https://www.php.net/archive/2026.php) and the 17 [php-src security advisories](https://github.com/php/php-src/security/advisories) of 2026-11-19

---

(c) 2026 АО «Сайбер ОК» / JSC CyberOK. Provided for informational and research
purposes only; see `LICENSE` for the full copyright and usage notice (RU + EN).
