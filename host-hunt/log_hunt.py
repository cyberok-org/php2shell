#!/usr/bin/env python3
# ------------------------------------------------------------------------
# CyberOK — php2shell defense tools, PHP-UP-2026-W2 (2026-11-19 release)
# (c) 2026 АО «Сайбер ОК» / JSC CyberOK — research/defensive use only.
# ------------------------------------------------------------------------
"""
log_hunt.py — grep PHP error logs and php-fpm master logs for traces of the
session-engine CVEs of the 2026-11-19 release (stdlib only, read-only).
Patterns were taken from lab runs on 8.5.12 vs 8.5.13 / 8.2.35 vs 8.2.36.

  129481  fatal raised from a stream_close() during shutdown + worker exit/crash
  129182  late shutdown fatals ("in Unknown on line 0": memory-limit restore,
          zlib/output_handler conflict) followed by worker crash
  129474  "Allowed memory size ... exhausted" fatal whose frame #0 is a magic-
          method trampoline-looking call, zend_mm_heap corrupted, worker SIGSEGV/SIGABRT
  115560  post-fix: "Session ini settings cannot be changed at runtime when
          session.upload_progress.enabled is On" (app uses the runtime switch while
          upload progress is ON) and "Failed to decode session object"
  126714  "Write wrote less bytes than requested" / "ftruncate() failed" (files handler)
Usage: log_hunt.py FILE_OR_DIR [...] [--json out.json]
Exit: 0 nothing · 1 hits · 2 error
"""
import argparse
import json
import os
import re
import sys

P = [
    ("129481", "HIGH", re.compile(r"\[internal function\]: [^\n]*->stream_close\(\)")),
    ("129481/129182", "MED", re.compile(r"child \d+ exited (?:on signal (?:6|11)|with code 1) ")),
    ("129182", "MED", re.compile(r"Failed to set memory limit to \d+ bytes \(Current memory usage is \d+ bytes\) in Unknown on line 0")),
    ("129182", "MED", re.compile(r"PHP Request Shutdown: Cannot use both zlib\.output_compression and output_handler")),
    ("129474", "MED", re.compile(r"zend_mm_heap corrupted")),
    ("129474", "LOW", re.compile(r"Allowed memory size of \d+ bytes exhausted.*\n(?:.*\n)?Stack trace:\n#0 [^\n]*\): [A-Za-z_\\][\w\\]*(?:::|->)\w+\(")),
    ("115560", "MED", re.compile(r"cannot be changed at runtime when session\.upload_progress\.enabled is On")),
    ("115560/126714", "LOW", re.compile(r"Failed to decode session object")),
    ("126714", "MED", re.compile(r"session_write_close\(\)[^\n]*Write wrote less bytes than requested|Write wrote less bytes than requested|ftruncate\(\) failed")),
]


def scan(path):
    try:
        text = open(path, encoding="latin1", errors="replace").read()
    except OSError as e:
        print(f"[ERR] {path}: {e}", file=sys.stderr)
        return []
    hits = []
    for cve, sev, rx in P:
        for m in rx.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            hits.append({"file": path, "line": line, "cve": cve, "severity": sev,
                         "match": m.group(0).replace("\n", " | ")[:200]})
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--json")
    a = ap.parse_args()
    files = []
    for p in a.paths:
        if os.path.isdir(p):
            for root, _, fs in os.walk(p):
                files += [os.path.join(root, f) for f in fs if f.endswith((".log", ".txt")) or "log" in f]
        else:
            files.append(p)
    hits = []
    for f in sorted(files):
        hits += scan(f)
    for h in hits:
        print(f"[{h['severity']:<4}] CVE-2026-{h['cve']:<14} {h['file']}:{h['line']}  {h['match']}")
    print(f"{len(files)} files, {len(hits)} hits")
    if a.json:
        json.dump(hits, open(a.json, "w"), indent=1)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
