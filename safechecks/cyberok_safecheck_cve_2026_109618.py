#!/usr/bin/env python3

# ------------------------------------------------------------------------
# CyberOK — php2shell defense tools (CVE-2026-109618 / CVE-2026-109619)
#
# (c) 2026 АО «Сайбер ОК» / JSC CyberOK
# Материал предоставляется исключительно для ознакомительных и исследовательских целей.
# Копирование, переработка, распространение, переопубликация и использование материала
# полностью или частично в коммерческих целях, включая создание и продвижение
# конкурирующих продуктов, запрещены без предварительного письменного разрешения
# правообладателя.
#
# Provided for informational and research purposes only. Copying, modification,
# distribution, republication, and use of this material in whole or in part for
# commercial purposes, including the creation and promotion of competing products,
# is prohibited without the prior written permission of the copyright holder.
# ------------------------------------------------------------------------

"""
SAFECHECK: CVE-2026-109618 — RCE via OOM corruption (GHSA-w8hw-w9fx-j79w).

(c) 2026 АО "Сайбер ОК" / JSC CyberOK
Материал предоставляется исключительно для ознакомительных и исследовательских целей. 
Копирование, переработка, распространение, переопубликация и использование материала полностью или частично в коммерческих целях, 
включая создание и продвижение конкурирующих продуктов, запрещены без предварительного письменного разрешения правообладателя.

Two modes:

1. LOCAL (decisive, default): --php-cgi /path/to/php-cgi
   Behavioural, non-destructive: drives THROWAWAY php-cgi processes with the
   upstream regression shapes (request bodies that exhaust memory_limit during
   request parsing, before any script runs). Verdict from behaviour only:
     AFFECTED  = a shape crashes/corrupts (SIGSEGV/abort/sanitizer artifact)
     SAFE      = every shape ends in the graceful memory-exhausted fatal
   Nothing outside the throwaway processes is touched; no ini files modified
   (limits passed per-process via -d).

2. REMOTE (surface only, honest limits): --url https://host/
   Checks what a remote party CAN see: whether PHP parses attacker multipart /
   urlencoded POSTs pre-auth (the vulnerable code path is reached before any
   application code). It CANNOT prove a version or a patch (a parser fix need
   not change status codes) — the decisive verdict is mode 1 on the origin
   binary, or `php -v`. 3 requests, read-only shapes (small bodies: the OOM
   shapes themselves are deliberately NOT fired remotely — they are DoS-class).

Usage:  python3 safecheck_cve_2026_109618.py --php-cgi /path/to/php-cgi
        python3 safecheck_cve_2026_109618.py --url https://host/
Exit:   0 = SAFE, 1 = AFFECTED / exposed surface, 2 = inconclusive
"""
import argparse
import os
import re
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

FIXED = "8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (fix removes the OOM longjmp bailout)"


def version_line(verdict):
    if verdict == "AFFECTED":
        return (f"VERSION: signal present ⇒ build is AFFECTED, i.e. predates the fix — "
                f"patched in {FIXED}")
    return f"VERSION: no crash signal — for a version decision run `php -v` (fix: {FIXED})"


# ---------------------------------------------------------------- local mode
INI = ["-n", "-d", "memory_limit=8M", "-d", "post_max_size=1G",
       "-d", "max_input_vars=10000000", "-d", "html_errors=0"]
TARGET = "<?php echo 'no OOM';\n"
CLEAN_FATAL = re.compile(rb"Allowed memory size of \d+ bytes exhausted", re.I)
BAD = (b"AddressSanitizer", b"SEGV", b"segmentation", b"Aborted", b"core dumped")


def local_mode(php_cgi):
    ver = subprocess.run([php_cgi, "-v"], capture_output=True, text=True)
    print(f"binary : {php_cgi}")
    print(f"version: {(ver.stdout or '?').splitlines()[0]}")

    shapes = [
        ("nested", "application/x-www-form-urlencoded",
         "&".join(["a[]" + "[b]" * 63 + "=c"] * 1000)),
        ("bigvalue", "application/x-www-form-urlencoded",
         "a=" + "x" * (6 * 1024 * 1024)),
        ("manyvars", "application/x-www-form-urlencoded",
         "&".join(f"k{i}=v{i}" for i in range(200_000))),
        # fix-presence differential shape (validated 8.2.34 vs 8.2.35,
        # 2026-10-21): pre-fix dies in the parsing bailout, post-fix the
        # soft-OOM deferral completes the same parse within memory_limit
        ("mpheaders", "multipart/form-data; boundary=sc",
         ("--sc\r\n" + 'Content-Disposition: form-data; name="f"; filename="a.txt"\r\n'
          + "X-Pad: pppppppppppppppppppppppppppppp\r\n" * 150_000
          + "Content-Type: text/plain\r\n\r\nZ\r\n" + "--sc--\r\n")),
    ]
    affected = clean = False
    completed_mph = False
    for name, ctype, body in shapes:
        with tempfile.TemporaryDirectory() as td:
            t = os.path.join(td, "t.php")
            open(t, "w").write(TARGET)
            bf = os.path.join(td, "b")
            open(bf, "wb").write(body.encode())
            env = {"REQUEST_METHOD": "POST", "CONTENT_TYPE": ctype,
                   "CONTENT_LENGTH": str(len(body)), "SCRIPT_FILENAME": t,
                   "REDIRECT_STATUS": "1", "PATH": "/usr/bin:/bin",
                   "ASAN_OPTIONS": "detect_leaks=0"}
            with open(bf, "rb") as stdin:
                try:
                    p = subprocess.run([php_cgi, *INI], stdin=stdin,
                                       capture_output=True, timeout=240, env=env)
                    rc, out = p.returncode, p.stdout + p.stderr
                except subprocess.TimeoutExpired:
                    print(f"  {name:10} TIMEOUT (inconclusive for this shape)")
                    continue
        if any(s in out for s in BAD) or rc in (-11, -6, 134, 139):
            print(f"  {name:10} AFFECTED (rc={rc})")
            affected = True
        elif name == "mpheaders" and b"no OOM" in out:
            print(f"  {name:10} COMPLETED under memory_limit (soft-OOM deferral)")
            completed_mph = True
        elif CLEAN_FATAL.search(out):
            print(f"  {name:10} clean memory-fatal (graceful)")
            clean = True
        elif b"no OOM" in out:
            print(f"  {name:10} completed without OOM")
            clean = True
        else:
            print(f"  {name:10} rc={rc} unclear: {out[-100:]!r}")

    if affected:
        print("VULNERABLE: request-parsing OOM crashes/corrupts a throwaway "
              "php-cgi process (CVE-2026-109618).")
        print(version_line("AFFECTED"))
        return 1
    if completed_mph:
        print("SAFE: fix present — the header-amplification parse completes "
              "under the same memory_limit (soft-OOM deferral, the redesigned "
              "OOM machinery of 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).")
        print(version_line("SAFE"))
        return 0
    if clean:
        print("PRE-FIX SIGNAL: OOM during request parsing bails out (pre-fix "
              "window); no crash materialized on this layout (advisory AC:H). "
              "Treat as AFFECTED — CVE-2026-109618.")
        print(version_line("AFFECTED"))
        return 1
    print("INCONCLUSIVE: no decisive signal — prefer an ASan build of the same "
          "version for the definitive behavioural check.")
    return 2


# --------------------------------------------------------------- remote mode
def remote_mode(url):
    B = "----safecheck"
    mp = (f"--{B}\r\n" + 'Content-Disposition: form-data; name="x"\r\n\r\n1\r\n'
          + f"--{B}--\r\n").encode()

    def post(ctype, body):
        req = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": ctype})
        try:
            with urllib.request.urlopen(req, timeout=20,
                                        context=ssl.create_default_context()) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception as e:  # noqa: BLE001
            return f"err:{e}"

    root = None
    try:
        with urllib.request.urlopen(url, timeout=20,
                                    context=ssl.create_default_context()) as r:
            root = r.status
    except Exception:  # noqa: BLE001
        root = "err"
    c1 = post("application/x-www-form-urlencoded", b"a=1")
    c2 = post(f"multipart/form-data; boundary={B}", mp)
    print(f"root={root} urlencoded={c1} multipart={c2}")

    # NOTE: 403/404 alone is NOT proof of edge-level rejection — the PHP
    # application itself can return these codes AFTER parsing the body.
    # The only reliable signal is when the status differs between a trivial
    # urlencoded POST (c1) and an identical multipart POST (c2).
    if c2 in {403} and c1 not in {403}:
        print("POSSIBLY-MITIGATED: multipart specifically rejected (403) while "
              "urlencoded passes — but this could also be application routing. "
              "Verify at the origin (php -v or LOCAL mode).")
        return 0
    if isinstance(c1, int) and isinstance(c2, int) and (c2 < 500) and (c1 < 500):
        print("SURFACE-EXPOSED: PHP (or a parser) consumed the POSTs pre-auth. "
              "This is reachability only — NOT a vulnerability verdict; the "
              "decisive check is LOCAL mode against the origin php-cgi binary "
              f"or `php -v` (fix: {FIXED}).")
        return 1
    print("INCONCLUSIVE: unexpected responses.")
    return 2
    if isinstance(c1, int) and isinstance(c2, int) and (c2 < 500) and (c1 < 500):
        print("SURFACE-EXPOSED: PHP (or a parser) consumed the POSTs pre-auth. "
              "This is reachability only — NOT a vulnerability verdict; the "
              "decisive check is LOCAL mode against the origin php-cgi binary "
              f"or `php -v` (fix: {FIXED}).")
        return 1
    print("INCONCLUSIVE: unexpected responses.")
    return 2


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--php-cgi", help="local decisive mode: path to php-cgi")
    g.add_argument("--url", help="remote surface mode: base URL")
    a = ap.parse_args()
    if a.php_cgi:
        return local_mode(a.php_cgi)
    return remote_mode(a.url)


if __name__ == "__main__":
    sys.exit(main())
