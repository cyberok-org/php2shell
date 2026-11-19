#!/usr/bin/env python3
# ------------------------------------------------------------------------
# CyberOK — PHP-UP-2026 wave 2 defense tools (PHP security release 2026-11-19)
# (c) 2026 АО «Сайбер ОК» / JSC CyberOK — provided for informational and research purposes
# only; see the kit LICENSE / header of the rule files for the full terms.
# ------------------------------------------------------------------------
"""
host-hunt: CVE-2026-128090 (GHSA-68fq-fh7h-f8gr) — Phar archives whose trusted
<archive>.pubkey sidecar is NOT enforced on unpatched PHP.

Flags every phar that has an adjacent "<file>.pubkey" but whose signature type is a keyless
hash (MD5/SHA-1/SHA-256/SHA-512) or that carries no signature at all. On PHP < 8.2.36 /
8.3.37 / 8.4.28 / 8.5.13 such an archive is accepted without consulting the public key —
exactly the state an attacker leaves behind after the downgrade (or a deployment that never
used OpenSSL signing in the first place). OpenSSL-typed signatures (0x10/0x11/0x12) are OK.

Formats: native phar (trailer [flags u32][GBMB]), tar-based and zip-based phars
(.phar/signature.bin, first u32 = flags). Read-only, stdlib only.

usage: phar_pubkey_scan.py [--json] [--all] PATH [PATH ...]
exit: 0 nothing flagged, 1 at least one FLAG, 2 usage/IO error
"""
import argparse
import io
import json
import os
import struct
import sys
import tarfile
import zipfile

SIG = {0x0001: "MD5", 0x0002: "SHA-1", 0x0003: "SHA-256", 0x0004: "SHA-512",
       0x0010: "OpenSSL", 0x0011: "OpenSSL_SHA256", 0x0012: "OpenSSL_SHA512"}
OPENSSL = {0x0010, 0x0011, 0x0012}
MAX_READ = 512 * 1024 * 1024


def sig_native(path):
    with open(path, "rb") as fh:
        fh.seek(0, 2)
        size = fh.tell()
        if size < 8:
            return None
        fh.seek(size - 8)
        tail = fh.read(8)
    if tail[4:] != b"GBMB":
        return None
    return struct.unpack("<I", tail[:4])[0]


def sig_tar(path):
    try:
        with tarfile.open(path, "r:*") as tf:
            for m in tf.getmembers():
                if m.name == ".phar/signature.bin" and m.isfile():
                    blob = tf.extractfile(m).read(8)
                    return struct.unpack("<I", blob[:4])[0] if len(blob) >= 4 else None
    except (tarfile.TarError, OSError, EOFError):
        return None
    return None


def sig_zip(path):
    """Read .phar/signature.bin RAW (stored entry) via the central directory. PHP does not check
    the zip CRC of signature.bin, so a downgraded archive usually has a stale CRC that makes
    zipfile.read() fail — parse the structures directly instead."""
    with open(path, "rb") as fh:
        data = fh.read(MAX_READ)
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > len(data):
        return None
    cdir = struct.unpack("<I", data[eocd + 16:eocd + 20])[0]
    rec = cdir
    while data[rec:rec + 4] == b"PK\x01\x02":
        method = struct.unpack("<H", data[rec + 10:rec + 12])[0]
        csize = struct.unpack("<I", data[rec + 20:rec + 24])[0]
        nlen, xlen, clen = struct.unpack("<HHH", data[rec + 28:rec + 34])
        local = struct.unpack("<I", data[rec + 42:rec + 46])[0]
        name = data[rec + 46:rec + 46 + nlen]
        if name == b".phar/signature.bin":
            lnlen, lxlen = struct.unpack("<HH", data[local + 26:local + 30])
            start = local + 30 + lnlen + lxlen
            blob = data[start:start + csize]
            if method == 8:
                import zlib
                blob = zlib.decompressobj(-15).decompress(blob)
            return struct.unpack("<I", blob[:4])[0] if len(blob) >= 4 else None
        rec += 46 + nlen + xlen + clen
    return None


def detect(path):
    """Return (format, flags|None)."""
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head[:2] == b"PK":
        return "zip", sig_zip(path)
    fl = sig_native(path)
    if fl is not None:
        return "native", fl
    if tarfile.is_tarfile(path):
        return "tar", sig_tar(path)
    return "native", None


def is_phar_candidate(name):
    n = name.lower()
    return n.endswith((".phar", ".phar.tar", ".phar.zip", ".phar.tgz", ".phar.gz", ".phar.bz2", ".phar.tar.gz"))


def scan_file(path):
    pub = path + ".pubkey"
    has_pub = os.path.isfile(pub)
    try:
        fmt, flags = detect(path)
    except OSError as e:
        return {"file": path, "status": "ERROR", "error": str(e)}
    sig = SIG.get(flags, "none" if flags is None else "0x%04x" % flags)
    rec = {"file": path, "format": fmt, "signature": sig, "pubkey": has_pub}
    if has_pub and (flags is None or flags not in OPENSSL):
        rec["status"] = "FLAG"
        rec["why"] = ("keyless %s signature with .pubkey sidecar: accepted WITHOUT the key on unpatched PHP "
                      "(CVE-2026-128090 downgrade state)" % sig) if flags is not None else \
                     "no signature but a .pubkey sidecar exists: integrity relies on phar.require_hash only"
        rec["severity"] = "high" if flags is not None else "medium"
    elif has_pub:
        rec["status"] = "OK"
    else:
        rec["status"] = "INFO-no-pubkey"
    return rec


def iter_targets(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
        elif os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for f in files:
                    if is_phar_candidate(f):
                        yield os.path.join(root, f)


def main(argv=None):
    ap = argparse.ArgumentParser(description="CVE-2026-128090 phar/.pubkey triage (read-only)")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--all", action="store_true", help="also list OK / no-pubkey archives")
    a = ap.parse_args(argv)
    results = [scan_file(f) for f in iter_targets(a.paths)]
    flagged = [r for r in results if r["status"] == "FLAG"]
    shown = results if a.all else flagged
    if a.json:
        print(json.dumps({"flagged": len(flagged), "scanned": len(results), "results": shown}, indent=2))
    else:
        for r in shown:
            print("%-14s %-6s %-15s pubkey=%-5s %s" % (r["status"], r.get("format", "?"), r.get("signature", "?"),
                                                       r.get("pubkey"), r["file"]))
            if r.get("why"):
                print("               -> " + r["why"])
        print("scanned=%d flagged=%d" % (len(results), len(flagged)), file=sys.stderr)
    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
