# PHP2Shell host hunt

[Русская инструкция](README.ru.md)

Read-only filesystem triage to complement the repository's [Sigma rules](../sigma/php2shell_http_exploit_attempt.yml). It checks selected webroots, file-backed PHP sessions, temporary/artifact directories, and saved HTTP request bodies. Indicators were reviewed on **2026-10-28**.

A match identifies a known sample, public PoC content, or a suspicious pattern according to the rule metadata. It does **not** automatically prove successful exploitation. No matches means only that the scanned files did not match these rules.

## Contents

| File | Purpose |
|---|---|
| [php2shell_hosthunt.yar](php2shell_hosthunt.yar) | Seven scoped rules with evidence class, confidence, sources, and caveats |
| [hosthunt.py](hosthunt.py) | Bounded directory traversal and JSONL findings; no PHP execution, deserialization, or network requests |
| [iocs.json](iocs.json) | Two exact payload hashes, dated network indicators, paths, and public PoC markers with their roles and sources |
| [test_hosthunt.py](test_hosthunt.py) | 25 offline regression tests using synthetic byte fixtures |
| [validation.json](validation.json) | Recorded validation environment, result, and limitations |

Network indicators in `iocs.json` are leads for DNS, proxy, firewall, and process telemetry. The runner does not search every file for these IP addresses or domains.

## Run

Use Python 3.10+ on the analysis machine. The recorded local validation used Python 3.12 and `yara-python` 4.5.4. From the **repository root**:

```bash
cd host-hunt
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest -v test_hosthunt

.venv/bin/python hosthunt.py \
  --webroot /mnt/server/var/www/html \
  --session-dir /mnt/server/var/lib/php/sessions \
  --artifact-dir /mnt/server/tmp \
  --artifact-dir /mnt/server/var/tmp \
  > findings.jsonl
```

Replace the example paths with directories belonging to the PHP instance under investigation. Each directory option is repeatable. Keep the analysis checkout, fixtures, and output reports outside the scanned evidence directories. A copy or snapshot is preferable for preserving evidence; reading live files can update atime, and concurrently changing files do not provide a consistent snapshot.

### Select the right scope

| Option | Scope |
|---|---|
| `--webroot` | Deployed web files: named PoC shell and generic PHP execution patterns |
| `--session-dir` | Only `sess_*` basenames, recursively: session content and progress-key patterns |
| `--artifact-dir` | Selected temporary/artifact directories: exact hashes, named shell, generic PHP patterns |
| `--capture-dir` | One raw, decoded HTTP request body per file: serialized integer-key sequence |

The exact malware hash rule applies in every scope. Use the effective `session.save_handler` and `session.save_path` of the **web SAPI/FPM pool**, including the correct container or mount. CLI configuration can differ. `--session-dir` does not inspect Redis/Memcached or other external backends. If the file backend uses `N;MODE;/path`, supply `/path`; the scanner visits its subdirectories.

For captured bodies, remove transport framing and compression using the appropriate evidence-processing tools first. The runner does not parse PCAP, reassemble TCP/HTTP, or decode URL/JSON escaping. From `host-hunt/`:

```bash
.venv/bin/python hosthunt.py \
  --capture-dir /mnt/evidence/decoded-http-bodies \
  --max-bytes 67108864 > capture-findings.jsonl
```

The default file limit is **8 MiB**, configurable up to **64 MiB**. Oversized, changing, inaccessible, archived/compressed, and special files are reported as skipped or errors. Symlinks are not followed; explicitly add a resolved target when it belongs in the analysis. Empty eligible roots and skipped files make the result incomplete.

The rules require YARA external variables `scope` and `filename`. The runner supplies both **for each file**. A recursive YARA invocation with one fixed `-d filename=...` does not provide equivalent filename handling.

## Interpret findings

| Rule suffix | Evidence class and limits |
|---|---|
| `Associated_Malware_Exact_SHA256` | Exact identity of a published malicious loader/bot. Does not establish initial access through these CVEs. |
| `PublicPoC_8512_Named_Shell` | Default `p2s_8512_shell.php` filename plus matching PHP content. Authorized testing may leave the same file. |
| `PublicPoC_Session_Webshell` | Two characteristic markers and execution function from a separate session-backed PoC. Stored code is not execution evidence. |
| `Session_UploadProgress_PHP` | PHP text with the default progress prefix in a session. User-supplied snippets/filenames and Safechecks may match. |
| `Session_Progress_ObjectSeed` | Object seed in a progress key, with bounded context. Ordinary `key|a:` or `key|O:` alone is insufficient. |
| `PHP_Direct_Request_Execution_Heuristic` | Generic direct request-variable-to-execution pattern. Not CVE-specific; misses obfuscation and variable indirection. |
| `Captured_Integer_Key_Sequence` | Captured request pattern inspired by Corelight SID 3000653. Not an installed-payload verdict. |

Full rule IDs and sources are in the YARA metadata. The two progress rules assume the default `upload_progress_` prefix. Code examples, administration tools, public PoCs, and authorized checks can match; false-positive rates have not been measured on a real application corpus.

`SC109619`, `ZZ_POSTPATCH_MARKER`, and `cyberok_test` are reported as possible test context. They never suppress a match automatically. Correlate findings with the test schedule, deployment baseline, logs, and endpoint telemetry.

### JSONL and exit status

Output includes `start`, `finding`, `skip`/`error`/`coverage`, and `summary` records. Findings contain path, size, mtime, SHA-256, rule IDs, and metadata. Matched session bytes and user tokens are not printed.

| Exit | Meaning |
|---|---|
| `1` | Findings require review. Also inspect `incomplete`; findings and partial coverage can coexist. |
| `2` | No findings, but incomplete coverage or an error. |
| `0` | `NO_MATCH_IN_SCANNED_SCOPE`. No claim that the host is uncompromised. |

`incomplete: false` only describes the explicitly selected roots and scope. Deleted files, process memory, external session backends, and artifacts outside those roots remain outside coverage. PHP's normal upload-progress cleanup can remove evidence after the POST completes.

## Relationship to Sigma and existing detections

The HTTP Sigma rule requires request-body telemetry; standard nginx combined access logs do not contain POST bodies or Cookie headers. The process rule requires actual process-creation events with parent/child fields. Neither YAML rules nor a filesystem scan can reconstruct historical telemetry that was never collected.

An OOM, session error, request to a known shell name, or contact with an indicator is a lead. Correlate it with unexpected file changes, a web-worker child process, or other execution evidence. The Russian guide includes optional `rg` commands for existing logs and configuration files.

## Sources

- [cowrAI, published 22 October; clarification 26 October](https://cowrai.com/research/php2shell-godofthunder/): associated loader/ELF hashes and delivery/C2 indicators. Sensors emulate PHP; malware was examined separately in a sandbox. Sample identity does not prove the entry vector.
- [0x4D31, 24 October](https://github.com/0x4D31/honeypot-data/blob/main/reports/php2shell/2026-10-24-confirmed-rce.md): process-confirmed RCE on single-worker mod_php honeypots. Request-body hashes from that report are not treated as malware file hashes here.
- [Rafalohaki, pinned PoC source](https://github.com/rafalohaki/php2shell-poc/tree/6102cff317b4b7ae9188fc8e82f6a4a64e6fd950): `p2s_8512_shell.php` and the `SHELL_ALIVE` / `PAYLOAD_PERSISTED sid=` session shell belong to different PoCs.
- [Corelight, pinned rule source](https://github.com/corelight/php2shell-detect/blob/3b3715aa6ce50b6c2a8b03d2863506645b364b98/suricata/php2shell.rules): integer-key sequence. This YARA rule is a separate request-body heuristic, not an exact transfer of Suricata engine semantics.
- [PHP session configuration](https://www.php.net/manual/en/session.configuration.php): progress data, cleanup, session storage, and configurable prefixes.
- [nginx logging](https://nginx.org/en/docs/http/ngx_http_log_module.html): fields in the combined log format.
- [MyCERT MA-1490.102026](https://www.mycert.org.my/portal/advisory?id=MA-1490.102026): additional YARA for exploit scripts. Those rules are not copied into this package, and the exploit tool need not be present on a remotely attacked host.

## Validation

Seven rules compiled without warnings with `yara-python` 4.5.4; all 25 offline tests passed. Tests cover normal sessions and objects, synthetic positive cases, renamed shells, test-marker context, per-file externals, size limits, symlinks, access errors, overlapping roots, and exit codes.

Hash-module plumbing is tested by substituting a benign fixture's digest into an in-memory copy of the rule. Published sample digests are checked against `iocs.json`. No real malware samples were downloaded or executed, and no target traffic or PHP execution is required by the tests. See [validation.json](validation.json) for the recorded environment.
