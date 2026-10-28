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

Two modes:

1. LOCAL (decisive): --php-cgi /path/to/php-cgi
   Behavioural: drives THROWAWAY php-cgi processes with the upstream
   regression shapes. Verdict from behaviour only.

2. REMOTE (non-destructive): --url https://host/  (or --list targets.txt)
   PortSwigger technique (credit: Tom SL): ONE POST with an invalid session
   ID (Cookie: PHPSESSID=_) + PHP_SESSION_UPLOAD_PROGRESS. On a vulnerable
   build PHP prints THREE warnings; the fix removes the third.

   phpMyAdmin special case: if the response contains 'phpMyAdmin', the
   target is retested at /show_config_errors.php which always shows errors
   regardless of display_errors (technique from Assetnote's scanner).

   Supports: --list file.txt (bulk targets, nuclei-style), -o results.json,
   --path /custom.php (custom path override), -t N (threads).

Exit codes per target: 0 = SAFE/patched, 1 = VULNERABLE, 2 = inconclusive.
With --list: returns 1 if ANY target is vulnerable, else 0.
"""
import argparse
import asyncio
import json
import os
import re
import ssl
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

# version-fix mapping
FIXED_VERSIONS = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
VERSION_PATTERN = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)")
PHPMYADMIN_MARKER = b"phpMyAdmin"
SHOW_CONFIG_ERRORS = "/show_config_errors.php"

# statuses that indicate edge rejection, NOT a PHP crash (Assetnote)
REJECTED_STATUSES = {400, 403, 411, 413, 414, 417, 422, 429, 431}


def _version_verdict(powered_by):
    m = VERSION_PATTERN.search(powered_by or "")
    if not m:
        return None
    major, minor, patch = int(m[1]), int(m[2]), int(m[3])
    fp = FIXED_VERSIONS.get((major, minor))
    if fp is None:
        return None
    return "FIXED" if patch >= fp else "VULNERABLE"


def _probe_url(url, timeout=20):
    """Send ONE non-destructive POST. Returns (status, body, powered_by)."""
    import urllib.request
    import urllib.error

    boundary = "----" + uuid.uuid4().hex[:32]
    token = uuid.uuid4().hex[:20]
    fname = uuid.uuid4().hex[:12] + ".txt"
    body = (f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            f"{token}\r\n"
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="f"; filename="{fname}"\r\n'
            "Content-Type: text/plain\r\n\r\n1\r\n"
            f"--{boundary}--\r\n").encode()

    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "Cookie": "PHPSESSID=_",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        })
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(16384), (r.headers.get("X-Powered-By") or "")
    except urllib.error.HTTPError as e:
        return e.code, e.read(16384), (e.headers.get("X-Powered-By") or "")
    except Exception as e:  # noqa: BLE001
        return None, str(e).encode(), ""


def _simple_get(url, timeout=10):
    """Send a minimal GET to check if the path itself is blocked."""
    import urllib.request
    import urllib.error
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=ssl.create_default_context()) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def remote_check(url, verbose=True):
    """Full remote check for a single URL. Returns dict with verdict."""
    result = {"url": url, "verdict": "INCONCLUSIVE", "exit_code": 2, "reason": ""}

    status, body, powered_by = _probe_url(url)
    result["status"] = status
    result["powered_by"] = powered_by or None

    if status is None:
        result["reason"] = f"unreachable: {body.decode('utf-8', 'replace')[:100]}"
        if verbose:
            print(f"  {url}  INCONCLUSIVE (unreachable)")
        return result

    # phpMyAdmin special case (Assetnote technique)
    if PHPMYADMIN_MARKER in body:
        # retest at show_config_errors.php
        pma_url = url.rstrip("/") + SHOW_CONFIG_ERRORS
        status2, body2, pb2 = _probe_url(pma_url)
        if status2 is not None:
            status, body, powered_by = status2, body2, pb2 or powered_by
            result["retested_at"] = pma_url

    resp_text = body.decode("utf-8", "replace")
    low = resp_text.lower()
    # w1 text differs across PHP generations: "Session ID ..." (>= 8.0) vs
    # "The session id ..." (7.x / 5.6) — match case-insensitively.
    w1 = "session id is too long or contains illegal characters" in low
    w2 = "failed to read session data" in low
    # w3 is the decisive signal: unpatched PHP attempts the session write
    # after start-up failure. On 5.6 w2 never fires, so do not require it.
    # NOTE: on PHP <= 7.4 these warnings reach the response only when the
    # target runs display_startup_errors=On (they are RINIT-time warnings).
    w3 = "failed to write session data (" in low

    if w1 and w3:
        result["verdict"] = "VULNERABLE"
        result["exit_code"] = 1
        result["reason"] = ("write-after-failure signature: unpatched PHP attempted "
                           "session write after start-up failure")
    elif w1 and w2:
        result["verdict"] = "PATCHED"
        result["exit_code"] = 0
        result["reason"] = ("two warnings (illegal SID + failed read) without "
                           "the write attempt — fix present")
    elif status in REJECTED_STATUSES:
        # A 4xx status does NOT prove edge rejection — the PHP application
        # itself can return 403/404 after fully parsing the body. Even a
        # matching GET→403 doesn't prove WHERE the rejection happened.
        # Always report as PROBE-REJECTED (inconclusive) unless version
        # evidence independently resolves the verdict.
        get_status = _simple_get(url, timeout=10)
        result["verdict"] = "PROBE-REJECTED"
        result["exit_code"] = 2
        result["reason"] = (f"POST→{status}, GET→{get_status}: rejection "
                           f"layer unknown (WAF or application)")
        # Version evidence can still resolve independently of the probe
        if powered_by:
            ver = _version_verdict(powered_by)
            if ver == "FIXED":
                result["verdict"] = "PATCHED (by version)"
                result["exit_code"] = 0
                result["reason"] = f"X-Powered-By reports patched: {powered_by}"
            elif ver == "VULNERABLE":
                result["verdict"] = "VULNERABLE (by version)"
                result["exit_code"] = 1
                result["reason"] = f"X-Powered-By reports unpatched: {powered_by}"
    else:
        ver = _version_verdict(powered_by)
        if ver == "VULNERABLE":
            result["verdict"] = "VULNERABLE (by version)"
            result["exit_code"] = 1
            result["reason"] = f"no crash signal but X-Powered-By reports unpatched: {powered_by}"
        elif ver == "FIXED":
            result["verdict"] = "PATCHED (by version)"
            result["exit_code"] = 0
            result["reason"] = f"X-Powered-By reports patched release: {powered_by}"
        else:
            result["reason"] = ("no session warnings (display_errors=Off?) "
                               "and no version advertised")

    if verbose:
        w = f" w1={int(w1)} w2={int(w2)} w3={int(w3)}"
        print(f"  {url}  {result['verdict']}  ({result['reason'][:80]}){w if verbose else ''}")
    return result


def bulk_scan(urls, threads=10, output=None):
    """Scan multiple URLs with thread pool."""
    results = []
    print(f"[*] scanning {len(urls)} target(s) with {threads} thread(s)")

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(remote_check, u): u for u in urls}
        for f in as_completed(futures):
            results.append(f.result())

    # sort by original order
    url_order = {u: i for i, u in enumerate(urls)}
    results.sort(key=lambda r: url_order.get(r["url"], 999))

    # summary — categories must sum to total (no orphans)
    vulnerable  = [r for r in results if r["verdict"].startswith("VULNERABLE")]
    confirmed_patched = [r for r in results if r["verdict"] in ("PATCHED", "PATCHED (by version)")]
    edge_rejected = [r for r in results if "MITIGATED" in r["verdict"] or "PROBE-REJECTED" in r["verdict"]]
    inconclusive = [r for r in results if r["exit_code"] == 2 and r not in vulnerable + confirmed_patched + edge_rejected]
    print(f"\n[*] RESULTS: {len(vulnerable)} vulnerable | "
          f"{len(confirmed_patched)} patched | "
          f"{len(edge_rejected)} edge_rejected | "
          f"{len(inconclusive)} inconclusive | "
          f"total={len(results)}")

    if output:
        import datetime as _dt
        with open(output, "w") as f:
            json.dump({"scanned_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                       "total": len(results),
                       "vulnerable": len(vulnerable),
                       "patched": len(confirmed_patched),
                       "edge_rejected": len(edge_rejected),
                       "inconclusive": len(inconclusive),
                       "categories_sum_check": len(vulnerable) + len(confirmed_patched) + len(edge_rejected) + len(inconclusive),
                       "results": results}, f, indent=2)
        print(f"[*] results saved to {output}")

    # exit 1 only when at least one is VULNERABLE; exit 0 only when ALL are
    # confirmed_patched or edge_rejected (no inconclusive); else exit 2
    if vulnerable:
        return 1
    if inconclusive:
        return 2
    return 0


# ------------------------------------------------------------------ local mode
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
                    print(f"  {name:10} TIMEOUT")
                    continue
        if any(s in out for s in BAD) or rc in (-11, -6, 134, 139):
            print(f"  {name:10} AFFECTED (rc={rc})")
            affected = True
        elif name == "mpheaders" and b"no OOM" in out:
            print(f"  {name:10} COMPLETED (soft-OOM deferral)")
            completed_mph = True
        elif CLEAN_FATAL.search(out):
            print(f"  {name:10} clean memory-fatal")
            clean = True
        elif b"no OOM" in out:
            print(f"  {name:10} completed")
            clean = True
        else:
            print(f"  {name:10} rc={rc} unclear")

    if affected:
        print("VULNERABLE: request-parsing OOM crashes a throwaway php-cgi.")
        return 1
    if completed_mph:
        print("SAFE: fix present (soft-OOM deferral completes the parse).")
        return 0
    if clean:
        print("PRE-FIX SIGNAL: OOM bails out during request parsing; no crash "
              "on this layout (advisory AC:H). Treat as AFFECTED.")
        return 1
    print("INCONCLUSIVE: prefer an ASan build for the definitive check.")
    return 2


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(
        description="CyberOK php2shell safe-check (CVE-2026-109618/109619)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--php-cgi", help="local decisive mode: path to php-cgi")
    g.add_argument("-u", "--url", help="remote mode: single URL or comma-separated")
    g.add_argument("-l", "--list", help="remote bulk mode: file with URLs (one per line)")
    ap.add_argument("-t", "--threads", type=int, default=10, help="bulk threads (default 10)")
    ap.add_argument("-o", "--output", help="save results to JSON file")
    ap.add_argument("--path", action="append", default=[],
                    help="custom path(s) to probe (default: /)")
    ap.add_argument("--timeout", type=int, default=20, help="request timeout")
    ap.add_argument("-q", "--quiet", action="store_true", help="suppress per-target output")
    a = ap.parse_args()

    if a.php_cgi:
        return local_mode(a.php_cgi)

    # collect URLs
    urls = []
    if a.url:
        for u in a.url.split(","):
            urls.append(u.strip())
    if a.list:
        with open(a.list) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)

    # apply custom paths
    if a.path:
        expanded = []
        for u in urls:
            base = u.split("?")[0].rstrip("/") or u.rstrip("/")
            for p in a.path:
                expanded.append(base + p)
        urls = expanded

    if not urls:
        print("ERROR: no targets specified", file=sys.stderr)
        return 2

    if len(urls) == 1:
        r = remote_check(urls[0], verbose=not a.quiet)
        if a.output:
            with open(a.output, "w") as f:
                json.dump(r, f, indent=2)
        return r["exit_code"]
    return bulk_scan(urls, a.threads, a.output)


if __name__ == "__main__":
    import subprocess
    import tempfile
    sys.exit(main())
