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
SAFECHECK: CVE-2026-109619 — RCE via stale global state (GHSA-6wmf-4rv5-p3rp).

Behavioural, local, non-destructive: spins a THROWAWAY single-worker php -S,
writes a poisoned session record (object of an undefined class) and sends ONE
multipart POST (PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS + file part). The
upload-progress handler decodes the session BEFORE RINIT:

  pre-fix  (<= 8.2.34 / 8.3.35 / 8.4.26 / 8.5.11): the full unserialize runs
            during request startup — with unserialize_callback_func set, the
            internal function is invoked there (observable via the warning
            "Function <name>() hasn't defined the class it was called for …
            in Unknown on line 0") = the user-code gap the advisory closes;
  post-fix (>= 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12): incomplete-classes-only
            decode, the callback never fires.

Usage:  python3 safecheck_cve_2026_109619.py --php-cli /path/to/php
Exit:   0 = SAFE (fix present), 1 = VULNERABLE (pre-RINIT callback fired), 2 = inconclusive
"""
import argparse
import os
import socket
import subprocess
import sys
import tempfile
import time

SID = "sc109619"
MARKER_TAIL = b"hasn't defined the class it was called for"
CLS = "SC109619"
POISON = (f"upload_progress_p|a:0:{{}}\n"
          f"x|O:{len(CLS)}:\"{CLS}\":0:{{}}\n").encode()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main():
    import argparse
    import json
    from concurrent.futures import ThreadPoolExecutor, as_completed

    ap = argparse.ArgumentParser(
        description="CyberOK php2shell safe-check — CVE-2026-109619 "
                    "(stale global state / pre-RINIT session decode)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--php-cli", help="local decisive mode: path to php CLI binary")
    g.add_argument("-u", "--url", help="remote mode: single URL (same probe as 109618)")
    g.add_argument("-l", "--list", help="remote bulk mode: file with URLs")
    ap.add_argument("-t", "--threads", type=int, default=10)
    ap.add_argument("-o", "--output", help="save results to JSON")
    ap.add_argument("--timeout", type=int, default=20)
    a = ap.parse_args()

    if a.php_cli:
        return local_mode(a.php_cli)

    # Remote mode: uses the same three-warning signature as 109618
    # (both CVEs share the same detection probe — the fix removes the
    # "Failed to write session data" warning from the response)
    import urllib.request
    import urllib.error
    import ssl
    import uuid

    def remote_check(url):
        result = {"url": url, "verdict": "INCONCLUSIVE", "exit_code": 2, "reason": ""}
        boundary = "----" + uuid.uuid4().hex[:32]
        body = (f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
                f"{uuid.uuid4().hex[:20]}\r\n"
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="f"; filename="a.txt"\r\n'
                "Content-Type: text/plain\r\n\r\n1\r\n"
                f"--{boundary}--\r\n").encode()
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={
                "Cookie": "PHPSESSID=_",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            })
        try:
            with urllib.request.urlopen(req, timeout=a.timeout,
                                        context=ssl.create_default_context()) as r:
                status, resp = r.status, r.read(16384).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status, resp = e.code, e.read(16384).decode("utf-8", "replace")
        except Exception as e:
            result["reason"] = f"unreachable: {e}"
            return result

        w1 = "Session ID is too long" in resp
        w2 = "Failed to read session data" in resp
        w3 = "Failed to write session data (" in resp

        if w1 and w2 and w3:
            result["verdict"] = "VULNERABLE"
            result["exit_code"] = 1
            result["reason"] = "unpatched PHP attempted session write after start-up failure"
        elif w1 and w2:
            result["verdict"] = "PATCHED"
            result["exit_code"] = 0
            result["reason"] = "fix present (incomplete-classes-only gate)"
        else:
            result["reason"] = "no session warnings (display_errors=Off?)"
        return result

    urls = []
    if a.url:
        urls.extend(u.strip() for u in a.url.split(","))
    if a.list:
        with open(a.list) as f:
            urls.extend(line.strip() for line in f if line.strip() and not line.startswith("#"))

    if not urls:
        print("ERROR: no targets", file=sys.stderr)
        return 2

    if len(urls) == 1:
        r = remote_check(urls[0])
        print(f"  {r['url']}  {r['verdict']}  ({r['reason'][:70]})")
        if a.output:
            with open(a.output, "w") as f:
                json.dump(r, f, indent=2)
        return r["exit_code"]

    results = []
    with ThreadPoolExecutor(max_workers=a.threads) as pool:
        for f in as_completed([pool.submit(remote_check, u) for u in urls]):
            r = f.result()
            results.append(r)
            print(f"  {r['url']}  {r['verdict']}")

    vuln = [r for r in results if r["exit_code"] == 1]
    print(f"\n[*] RESULTS: {len(vuln)} vulnerable | "
          f"{len(results) - len(vuln)} not vulnerable")
    if a.output:
        with open(a.output, "w") as f:
            json.dump({"total": len(results), "vulnerable": len(vuln),
                       "results": results}, f, indent=2)
    return 1 if vuln else 0


if __name__ == "__main__":
    sys.exit(main())
