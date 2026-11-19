#!/usr/bin/env python3
# ------------------------------------------------------------------------
# CyberOK — php2shell defense tools, PHP-UP-2026-W2 (2026-11-19 release)
# (c) 2026 АО «Сайбер ОК» / JSC CyberOK — research/defensive use only.
# ------------------------------------------------------------------------
"""
session_store_hunt.py — read-only hunt over PHP `files` session stores for
CVE-2026-126714 (spliced / partially overwritten session files) and
CVE-2026-115560 (serializer-mismatch seeds planted via upload progress).

Pure-Python re-implementation of PHP's three session decoders (php,
php_binary, php_serialize) and of the unserialize grammar. Nothing is
executed or instantiated; files are only read.

Findings (severity):
  HIGH  SPLICE_SEAM_IN_TAIL   php decode stops early and the undecoded tail holds
                              a record seam + object ( ";name|O:n:" ) — the shape of a
                              NEW-prefix + OLD-suffix splice (126714)
  HIGH  CROSS_HANDLER_OBJECT  data decodes cleanly under one handler WITHOUT objects
                              but yields objects under another (php / php_binary)
                              — a mismatch payload sitting in the store (115560)
  HIGH  PROGRESS_KEY_PAYLOAD  an upload_progress_* key contains '|' + serialized
                              syntax or object syntax (115560 seed)
  MED   SEAM_IN_STRING        a stored string value contains ";name|O:n:" (splice seed,
                              126714 preparation) or "|O:n:" (mismatch seed)
  MED   DECODE_FAIL           file does not decode under any handler (corruption,
                              interrupted write, mismatch)
  LOW   OBJECTS_PRESENT       objects stored in the session (class names listed;
                              legitimate for many apps — baseline them)
  INFO  UPLOAD_PROGRESS_KEY   upload progress records present (feature in use;
                              done=true left behind => cleanup=0)
Usage:
  session_store_hunt.py [DIR ...] [--handler auto|php|php_binary|php_serialize]
                        [--json out.json] [--max-bytes N]
  default DIRs: /var/lib/php/sessions /var/lib/php/session /var/lib/php5 /tmp
Exit: 0 nothing HIGH/MED · 1 findings HIGH/MED · 2 error
"""
import argparse
import glob
import json
import os
import re
import sys

SEAM = re.compile(rb'";[A-Za-z0-9_\-]{0,64}\|[OC]:\d{1,5}:"')
PIPE_OBJ = re.compile(rb'\|(?:[OC]:\d{1,5}:"|a:\d{1,7}:\{|s:\d{1,9}:")')
OBJ = re.compile(rb'[OC]:\d{1,5}:"[A-Za-z_\\\x80-\xff]')


class Fail(Exception):
    def __init__(self, pos, why):
        super().__init__(why)
        self.pos, self.why = pos, why


def _num(buf, p, term, allow_sign=True, allow_float=False):
    m = (re.compile(rb"[+-]?(?:\d+(?:\.\d*)?(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?|INF|NAN|-INF)")
         if allow_float else re.compile(rb"[+-]?\d+" if allow_sign else rb"\d+")).match(buf, p)
    if not m:
        raise Fail(p, "number")
    e = m.end()
    if buf[e:e + 1] != term:
        raise Fail(e, f"expected {term!r}")
    return m.group(0), e + 1


def parse(buf, p, objs, depth=0):
    """Parse one serialized value at p; return new position. Records class names in objs."""
    if depth > 512:
        raise Fail(p, "depth")
    t = buf[p:p + 1]
    if t == b"N":
        if buf[p + 1:p + 2] != b";":
            raise Fail(p, "N")
        return p + 2
    if t in (b"b", b"i", b"d", b"r", b"R"):
        if buf[p + 1:p + 2] != b":":
            raise Fail(p, t.decode())
        _, e = _num(buf, p + 2, b";", allow_float=(t == b"d"))
        return e
    if t in (b"s", b"S"):
        if buf[p + 1:p + 2] != b":":
            raise Fail(p, "s")
        n, e = _num(buf, p + 2, b":", allow_sign=False)
        n = int(n)
        if buf[e:e + 1] != b'"':
            raise Fail(e, 's"')
        if t == b"s":
            end = e + 1 + n
        else:  # S: escaped \xx counts as one char
            q, cnt = e + 1, 0
            while cnt < n:
                q += 3 if buf[q:q + 1] == b"\\" else 1
                cnt += 1
            end = q
        if end + 2 > len(buf) or buf[end:end + 2] != b'";':
            raise Fail(end, "string end")
        return end + 2
    if t == b"E":
        n, e = _num(buf, p + 2, b":", allow_sign=False)
        end = e + 1 + int(n)
        if buf[e:e + 1] != b'"' or buf[end:end + 2] != b'";':
            raise Fail(e, "E")
        objs.append(("enum", buf[e + 1:end].decode("latin1")))
        return end + 2
    if t == b"a":
        n, e = _num(buf, p + 2, b":", allow_sign=False)
        if buf[e:e + 1] != b"{":
            raise Fail(e, "a{")
        q = e + 1
        for _ in range(int(n)):
            if buf[q:q + 1] not in (b"i", b"s", b"S"):
                raise Fail(q, "array key")
            q = parse(buf, q, objs, depth + 1)
            q = parse(buf, q, objs, depth + 1)
        if buf[q:q + 1] != b"}":
            raise Fail(q, "a}")
        return q + 1
    if t in (b"O", b"C"):
        n, e = _num(buf, p + 2, b":", allow_sign=False)
        if buf[e:e + 1] != b'"':
            raise Fail(e, 'O"')
        cend = e + 1 + int(n)
        cls = buf[e + 1:cend]
        if buf[cend:cend + 2] != b'":':
            raise Fail(cend, "class end")
        objs.append(("object" if t == b"O" else "custom", cls.decode("latin1")))
        cnt, q = _num(buf, cend + 2, b":", allow_sign=False)
        if buf[q:q + 1] != b"{":
            raise Fail(q, "O{")
        q += 1
        if t == b"C":
            q += int(cnt)
        else:
            for _ in range(int(cnt)):
                q = parse(buf, q, objs, depth + 1)
                q = parse(buf, q, objs, depth + 1)
        if buf[q:q + 1] != b"}":
            raise Fail(q, "O}")
        return q + 1
    raise Fail(p, f"type {t!r}")


def decode(buf, handler):
    """Return dict(ok, consumed, keys, objs, fail_pos, why) emulating PHP's decoder."""
    keys, objs, p, n = [], [], 0, len(buf)
    try:
        if handler == "php_serialize":
            if not buf:
                return {"ok": True, "consumed": 0, "keys": [], "objs": [], "fail_pos": None, "why": ""}
            if buf[:2] != b"a:":
                raise Fail(0, "not an array")
            nk, e = _num(buf, 2, b":", allow_sign=False)
            q = e + 1
            for _ in range(int(nk)):
                k0 = q
                q = parse(buf, q, [], 1)
                keys.append(buf[k0:q])
                q = parse(buf, q, objs, 1)
            if buf[q:q + 1] != b"}":
                raise Fail(q, "a}")
            p = q + 1
        elif handler == "php":
            while p < n:
                q = buf.find(b"|", p)
                if q < 0:
                    raise Fail(p, "no delimiter")
                keys.append(buf[p:q])
                p = parse(buf, q + 1, objs)
        elif handler == "php_binary":
            while p < n:
                ln = buf[p] & 0x7F
                if p + ln >= n:
                    raise Fail(p, "binary key length")
                keys.append(buf[p + 1:p + 1 + ln])
                p = parse(buf, p + 1 + ln, objs)
        return {"ok": True, "consumed": p, "keys": keys, "objs": objs, "fail_pos": None, "why": ""}
    except (Fail, IndexError, ValueError) as ex:
        pos = getattr(ex, "pos", p)
        return {"ok": False, "consumed": p, "keys": keys, "objs": objs, "fail_pos": pos,
                "why": getattr(ex, "why", str(ex))}


def scan_file(path, handler, max_bytes):
    buf = open(path, "rb").read(max_bytes)
    out = {"file": path, "size": os.path.getsize(path), "findings": []}

    def add(sev, code, detail):
        out["findings"].append({"severity": sev, "code": code, "detail": detail})
    if not buf:
        return out
    handlers = ["php", "php_binary", "php_serialize"]
    res = {h: decode(buf, h) for h in handlers}
    clean = [h for h in handlers if res[h]["ok"] and res[h]["consumed"] == len(buf)]
    primary = handler if handler != "auto" else (clean[0] if clean else None)
    out["decodes_cleanly_as"] = clean
    if handler != "auto" and handler not in clean:
        add("MED", "DECODE_FAIL", f"not decodable as configured handler {handler}: "
            f"{res[handler]['why']} at byte {res[handler]['fail_pos']}")
    if not clean:
        add("MED", "DECODE_FAIL", "; ".join(f"{h}: {res[h]['why']}@{res[h]['fail_pos']}" for h in handlers))
    # splice: php decode stopped early, seam+object in the undecoded tail
    r = res["php"]
    if not r["ok"]:
        tail = buf[r["consumed"]:]
        if SEAM.search(tail) or (r["objs"] and SEAM.search(buf)):
            add("HIGH", "SPLICE_SEAM_IN_TAIL",
                f"php decoder stopped at byte {r['fail_pos']} ({r['why']}); objects before failure: "
                f"{[c for _, c in r['objs']]}; seam in undecoded data")
    # cross-handler objects
    if primary:
        base_objs = {c for _, c in res[primary]["objs"]}
        for h in ("php", "php_binary"):
            if h == primary:
                continue
            extra = [c for _, c in res[h]["objs"] if c not in base_objs]
            if extra:
                add("HIGH", "CROSS_HANDLER_OBJECT",
                    f"clean as {primary} (objects {sorted(base_objs) or 'none'}) but {h} reader "
                    f"instantiates {extra} (decoder {'ok' if res[h]['ok'] else 'fails after creating them'})")
    # upload progress keys
    keys = res[primary]["keys"] if primary else []
    if not keys:
        keys = [k for h in handlers for k in res[h]["keys"]]
    for k in keys:
        if b"upload_progress_" in k:
            if PIPE_OBJ.search(k) or OBJ.search(k):
                add("HIGH", "PROGRESS_KEY_PAYLOAD", f"upload-progress key carries serialized syntax: {k[:160]!r}")
            else:
                add("INFO", "UPLOAD_PROGRESS_KEY", f"{k[:80]!r}")
    # seams inside stored strings
    for m in SEAM.finditer(buf):
        add("MED", "SEAM_IN_STRING", f"record seam + object at byte {m.start()}: {buf[m.start():m.start() + 60]!r}")
        break
    if primary and res[primary]["objs"]:
        add("LOW", "OBJECTS_PRESENT", sorted({c for _, c in res[primary]["objs"]})[:20])
    return out


def main():
    ap = argparse.ArgumentParser(description="Hunt PHP session stores for CVE-2026-126714/115560 artefacts")
    ap.add_argument("dirs", nargs="*")
    ap.add_argument("--handler", default="auto", choices=["auto", "php", "php_binary", "php_serialize"])
    ap.add_argument("--json")
    ap.add_argument("--max-bytes", type=int, default=4 * 1024 * 1024)
    a = ap.parse_args()
    dirs = a.dirs or [d for d in ("/var/lib/php/sessions", "/var/lib/php/session", "/var/lib/php5", "/tmp")
                      if os.path.isdir(d)]
    results, worst = [], 0
    for d in dirs:
        for fn in sorted(glob.glob(os.path.join(d, "**", "sess_*"), recursive=True)):
            try:
                r = scan_file(fn, a.handler, a.max_bytes)
            except (OSError, PermissionError) as e:
                print(f"[ERR] {fn}: {e}", file=sys.stderr)
                continue
            results.append(r)
            for f in r["findings"]:
                if f["severity"] in ("HIGH", "MED"):
                    worst = 1
                print(f"[{f['severity']:<4}] {f['code']:<21} {fn}  {f['detail']}")
    print(f"scanned {len(results)} session files in {len(dirs)} dir(s); "
          f"{sum(1 for r in results if any(f['severity'] in ('HIGH', 'MED') for f in r['findings']))} flagged")
    if a.json:
        json.dump(results, open(a.json, "w"), indent=1, default=str)
    return worst


if __name__ == "__main__":
    sys.exit(main())
