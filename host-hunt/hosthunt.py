#!/usr/bin/env python3
"""Read-only, bounded filesystem YARA triage. No PHP execution or network I/O.

JSONL stdout contains paths/metadata, never matched session contents.
Exit 1: findings (check incomplete flag too); 2: incomplete without findings;
0: no matches IN THE SCANNED SCOPE, never a clean-host verdict.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

MAX_RULE_BYTES = 64 * 1024 * 1024
ARCHIVES = {".gz", ".bz2", ".xz", ".zip", ".7z", ".zst", ".tar"}
SELFTEST_MARKERS = (b"SC109619", b"ZZ_POSTPATCH_MARKER", b"cyberok_test")


def emit(record):
    print(json.dumps(record, ensure_ascii=True, sort_keys=True))


def run(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    for flag in ("webroot", "session-dir", "artifact-dir", "capture-dir"):
        ap.add_argument("--" + flag, action="append", default=[], metavar="PATH")
    ap.add_argument("--max-bytes", type=int, default=8 * 1024 * 1024,
                    help="per-file read cap, default 8 MiB; maximum 64 MiB")
    ap.add_argument("--timeout", type=int, default=10,
                    help="YARA seconds per file, default 10")
    ap.add_argument("--rules", type=Path,
                    default=Path(__file__).with_name("php2shell_hosthunt.yar"))
    args = ap.parse_args(argv)
    roots = [(scope, p) for scope, values in (
        ("web", args.webroot), ("session", args.session_dir),
        ("artifact", args.artifact_dir), ("capture", args.capture_dir))
        for p in values]
    if not roots:
        ap.error("provide at least one explicit scan root")
    if not 0 < args.max_bytes <= MAX_RULE_BYTES or args.timeout < 1:
        ap.error("max-bytes must be 1..67108864 and timeout must be positive")
    counts = dict(scanned=0, matched_files=0, rule_matches=0, skipped=0,
                  errors=0, excluded_by_scope=0, empty_roots=0)
    try:
        import yara
        rules = yara.compile(filepath=str(args.rules),
                             externals={"scope": "unscoped", "filename": ""})
    except Exception as exc:
        emit({"type": "error", "operation": "load_rules", "error": str(exc)})
        emit({"type": "summary", "verdict": "INCOMPLETE", "incomplete": True,
              "exit_code": 2, **counts})
        return 2

    def skipped(path, reason, error=False):
        counts["errors" if error else "skipped"] += 1
        emit({"type": "error" if error else "skip", "path": str(path),
              "reason": reason})

    def candidates(root):
        # DirEntry checks avoid following directory symlinks. Scan snapshots
        # for stable forensic results; live paths can still change concurrently.
        stack = [root]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as items:
                    for item in items:
                        if item.is_symlink():
                            skipped(item.path, "symlink_not_followed")
                        elif item.is_dir(follow_symlinks=False):
                            stack.append(Path(item.path))
                        elif item.is_file(follow_symlinks=False):
                            yield Path(item.path)
                        else:
                            skipped(item.path, "not_regular_file")
            except OSError as exc:
                skipped(current, str(exc), error=True)

    seen = set()
    emit({"type": "start", "utc": dt.datetime.now(dt.timezone.utc).isoformat(),
          "rules": str(args.rules), "yara_version": yara.__version__,
          "max_bytes": args.max_bytes, "roots": roots,
          "session_scope": "sess_* basenames only; filesystem backend only",
          "capture_scope": "raw decoded request bodies; archives not unpacked"})
    for scope, root_value in roots:
        root = Path(os.path.abspath(os.path.expanduser(root_value)))
        try:
            mode = root.lstat().st_mode
        except OSError as exc:
            skipped(root, str(exc), error=True)
            continue
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            skipped(root, "root_must_be_real_directory", error=True)
            continue
        before = counts["scanned"]
        already_covered = False
        for path in candidates(root):
            if scope == "session" and not path.name.startswith("sess_"):
                counts["excluded_by_scope"] += 1
                continue
            key = (scope, str(path))
            if key in seen:
                already_covered = True
                continue
            seen.add(key)
            if path.suffix.lower() in ARCHIVES:
                skipped(path, "compressed_or_archive_requires_separate_extraction")
                continue
            fd = None
            try:
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                fd = os.open(path, flags)
                first = os.fstat(fd)
                if not stat.S_ISREG(first.st_mode):
                    skipped(path, "not_regular_file_at_open")
                    continue
                if first.st_size > args.max_bytes:
                    skipped(path, "oversize")
                    continue
                with os.fdopen(fd, "rb") as stream:
                    fd = None
                    data = stream.read(args.max_bytes + 1)
                    last = os.fstat(stream.fileno())
                if len(data) > args.max_bytes:
                    skipped(path, "grew_beyond_read_cap")
                    continue
                if (first.st_size, first.st_mtime_ns, first.st_ctime_ns) != (
                        last.st_size, last.st_mtime_ns, last.st_ctime_ns):
                    skipped(path, "file_changed_during_read")
                    continue
                matches = rules.match(data=data, timeout=args.timeout,
                                      externals={"scope": scope, "filename": path.name})
            except Exception as exc:
                skipped(path, str(exc), error=True)
                continue
            finally:
                if fd is not None:
                    os.close(fd)
            counts["scanned"] += 1
            if matches:
                counts["matched_files"] += 1
                counts["rule_matches"] += len(matches)
                emit({"type": "finding", "path": str(path), "scope": scope,
                      "size": len(data), "mtime_ns": last.st_mtime_ns,
                      "sha256": hashlib.sha256(data).hexdigest(),
                      "known_test_markers_present": [x.decode("ascii") for x in SELFTEST_MARKERS if x in data],
                      "matches": [{"rule": m.rule, "tags": m.tags, "meta": m.meta} for m in matches],
                      "interpretation": "triage_required_not_automatic_compromise"})
        if counts["scanned"] == before and not already_covered:
            counts["empty_roots"] += 1
            emit({"type": "coverage", "path": str(root), "scope": scope,
                  "reason": "no_new_eligible_files_scanned"})
    incomplete = bool(counts["skipped"] or counts["errors"] or counts["empty_roots"])
    if counts["matched_files"]:
        verdict, code = "MATCHES_REVIEW_REQUIRED", 1
    elif incomplete:
        verdict, code = "INCOMPLETE", 2
    else:
        verdict, code = "NO_MATCH_IN_SCANNED_SCOPE", 0
    emit({"type": "summary", "verdict": verdict, "incomplete": incomplete,
          "exit_code": code, **counts})
    return code


if __name__ == "__main__":
    sys.exit(run())
