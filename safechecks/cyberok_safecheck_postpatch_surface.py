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
SAFECHECK: post-patch surface — session upload-progress poisoning exposure.

This check does NOT test whether PHP is vulnerable to CVE-2026-109618/109619
(those are closed by 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12). It tests whether your
CONFIGURATION remains exposed to the session-poisoning surface that SURVIVES
the patch — the path documented in public exploit research (xue-poc paths 6-8).

What it checks (against a throwaway local PHP process, non-destructive):

  1. FORM-SID INGESTION (survives all versions by design):
     A multipart form field named PHPSESSID sets the session id before the
     script runs, bypassing session.use_only_cookies=On. If this succeeds,
     an attacker can choose the session file path deterministically.

  2. PROGRESS-KEY PERSISTENCE (config-dependent):
     With session.upload_progress.cleanup=0, the attacker-controlled
     PHP_SESSION_UPLOAD_PROGRESS value becomes a $_SESSION key verbatim and
     is serialized into the session file. If the file contains the raw
     attacker bytes, the poisoning surface is live.

  3. SERIALIZED PAYMENTLOAD LANDS IN SESSION FILE:
     The poisoned key (containing PHP open tags or serialized object syntax)
     is written to the session file on disk. An application-level
     include/LFI or unserialize() sink converts this to code execution.

  4. HANDLER MISMATCH PRECONDITION:
     If the session save_path is shared between directories with different
     serialize_handler settings (php vs php_serialize), a mismatch
     deserialization attack becomes possible.

This safecheck is CONFIGURATION-reachability only: a "surface exposed" verdict
means the preconditions for the post-patch attack chain exist; it does NOT
mean your application has the required sink (include/LFI/unserialize).

Usage:  python3 cyberok_safecheck_postpatch_surface.py --php-cli /path/to/php
Exit:   0 = surface mitigated, 1 = surface exposed, 2 = inconclusive
"""
import argparse
import os
import socket
import subprocess
import sys
import tempfile
import time

SID = "postpatch01"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def read_production_config(php_cli):
    """Read the effective php.ini values. Returns (config, all_ok)."""
    directives = [
        "session.upload_progress.enabled",
        "session.upload_progress.cleanup",
        "session.serialize_handler",
        "session.use_strict_mode",
        "session.save_path",
    ]
    config = {}
    errors = []
    for d in directives:
        try:
            r = subprocess.run(
                [php_cli, "-r", f"echo ini_get('{d}');"],
                capture_output=True, text=True, timeout=10)
            if r.returncode != 0:
                errors.append(d)
                config[d] = "READ_ERROR"
            else:
                config[d] = r.stdout.strip()
        except Exception as e:
            errors.append(d)
            config[d] = f"READ_ERROR({type(e).__name__})"
    return config, errors


def check_production_config(config):
    """Check if the PRODUCTION config has the post-patch surface exposed.
    Returns (exposed_list, has_errors)."""
    print("--- PRODUCTION CONFIG (CLI SAPI — web SAPI may differ) ---")
    for k, v in config.items():
        print(f"  {k} = {v!r}")

    has_errors = any(v.startswith("READ_ERROR") for v in config.values())
    if has_errors:
        return [], True

    # ini_get returns "" for Off boolean directives (PHP manual)
    # So "" for upload_progress.enabled means DISABLED, not enabled
    enabled_raw = config.get("session.upload_progress.enabled", "")
    upload_enabled = enabled_raw in ("1", "On", "on", "true", "True")

    handler = config.get("session.serialize_handler", "")
    # PHP default serialize_handler is 'php', NOT php_serialize
    if handler == "":
        handler = "php"  # documented default

    exposed = []
    if upload_enabled:
        exposed.append("upload_progress.enabled=1 (surface reachable)")
        cleanup = config.get("session.upload_progress.cleanup", "")
        # "" means On (default), "0" means Off
        if cleanup == "0":
            exposed.append("upload_progress.cleanup=0 (poisoning persists)")
    if handler in ("php_binary", "php_serialize"):
        exposed.append(f"serialize_handler={handler!r} (CVE-2026-115560 precondition)")

    return exposed, False


def check_form_sid(php_cli, docroot, sessdir, cleanup):
    """Test 1+2: can a multipart field set the session id and persist content?"""
    port = free_port()
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
    ini = [
        "-d", "session.upload_progress.enabled=1",
        "-d", f"session.upload_progress.cleanup={cleanup}",
        "-d", "session.upload_progress.min_freq=0",
        "-d", "session.save_path=" + sessdir,
        "-d", "session.serialize_handler=php_serialize",
        "-d", "display_errors=1", "-d", "html_errors=0",
    ]
    srv = subprocess.Popen(
        [php_cli, "-n", "-S", f"127.0.0.1:{port}", "-t", docroot, *ini],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(1.5)

    b = "----postpatch"
    marker = "ZZ_POSTPATCH_MARKER"
    body = (f"--{b}\r\n"
            'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
            f"{SID}\r\n"
            f"--{b}\r\n"
            'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            f"{marker}\r\n"
            f"--{b}\r\n"
            'Content-Disposition: form-data; name="f"; filename="a.txt"\r\n'
            "Content-Type: text/plain\r\n\r\nZ\r\n"
            f"--{b}--\r\n").encode()
    req = (f"POST /index.php HTTP/1.1\r\nHost: h\r\n"
           f"Content-Type: multipart/form-data; boundary={b}\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body

    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=15)
        s.sendall(req)
        out = b""
        while True:
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            out += d
        s.close()
    finally:
        srv.terminate()
        try:
            srv.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            srv.kill()

    sess_file = os.path.join(sessdir, f"sess_{SID}")
    sess_content = b""
    if os.path.exists(sess_file):
        with open(sess_file, "rb") as f:
            sess_content = f.read()

    return {
        "http_200": b"200" in out.split(b"\r\n", 1)[0] if out else False,
        "sess_created": os.path.exists(sess_file),
        "sess_size": len(sess_content),
        "marker_present": marker.encode() in sess_content,
        "sess_content": sess_content[:300],
    }


def check_handler_mismatch(php_cli, docroot, sessdir):
    """Test 4: does the php handler decode php_serialize data destructively?"""
    # write a php_serialize-format session file
    sid = "mismatch_check"
    sess_path = os.path.join(sessdir, f"sess_{sid}")
    # php_serialize stores: a:1:{s:N:"key";s:M:"value";}
    # php handler would try to split at "|" and unserialize the value
    payload = 'a:1:{s:34:"upload_progress_|O:4:"Evil":1:{}";a:0:{}}'
    with open(sess_path, "w") as f:
        f.write(payload)

    # now read it back with the php handler
    port = free_port()
    reader = os.path.join(docroot, "reader.php")
    with open(reader, "w") as f:
        f.write(f"""<?php
session_id('{sid}');
ini_set('session.serialize_handler', 'php');
session_start();
echo "SESSION=" . json_encode($_SESSION) . "\\n";
echo "SID=" . session_id() . "\\n";
""")

    env = dict(os.environ)
    srv = subprocess.Popen(
        [php_cli, "-n", "-S", f"127.0.0.1:{port}", "-t", docroot,
         "-d", f"session.save_path={sessdir}",
         "-d", "session.serialize_handler=php",
         "-d", "display_errors=1", "-d", "html_errors=0"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(1.5)
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.sendall(f"GET /reader.php HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n".encode())
        out = b""
        while True:
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            if not d:
                break
            out += d
        s.close()
    finally:
        srv.terminate()
        try:
            srv.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            srv.kill()

    return {
        "response": out[:400],
        "destructive_decode": b"Evil" in out or b"Failed to decode" in out,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--php-cli", required=True, help="path to php CLI binary")
    ap.add_argument("--check-config", action="store_true",
                    help="check production php.ini only (no dynamic test)")
    a = ap.parse_args()

    td = tempfile.mkdtemp(prefix="postpatch-")
    www, sess = os.path.join(td, "www"), os.path.join(td, "sess")
    os.makedirs(www)
    os.makedirs(sess)
    with open(os.path.join(www, "index.php"), "w") as f:
        f.write("<?php echo 'ok';\n")

    if a.check_config:
        print("=== PRODUCTION CONFIG CHECK (CVE-2026-115560 + post-patch surface) ===")
        print(f"PHP binary: {a.php_cli}")
        ver = subprocess.run([a.php_cli, "-v"], capture_output=True, text=True)
        print(f"Version:    {(ver.stdout or '?').splitlines()[0]}")
        print()
        config, errors = read_production_config(a.php_cli)
        exposed, has_errors = check_production_config(config)
        print()
        if has_errors:
            print("VERDICT: INCONCLUSIVE — could not read PHP configuration.")
            print("  Errors in:", ", ".join(errors) if errors else "unknown")
            return 2
        if exposed:
            print("VERDICT: CLI CONFIG EXPOSED (web SAPI may differ):")
            for e in exposed:
                print(f"  • {e}")
            print("\nMITIGATION: session.upload_progress.enabled = 0")
            return 1
        print("VERDICT: CLI CONFIG CLOSED (web SAPI may differ — verify FPM/Apache pool)")
        return 0

    print("=== POST-PATCH SURFACE CHECK (not a CVE test) ===")
    print(f"PHP binary: {a.php_cli}")
    ver = subprocess.run([a.php_cli, "-v"], capture_output=True, text=True)
    print(f"Version:    {(ver.stdout or '?').splitlines()[0]}")
    print()

    # -- Test 1+2: form-sid + progress-key persistence (cleanup=0) --
    print("--- Test 1+2: form-SID ingestion + progress-key persistence (cleanup=0) ---")
    r0 = check_form_sid(a.php_cli, www, sess, cleanup=0)
    print(f"  session file created:  {r0['sess_created']}")
    print(f"  session file size:     {r0['sess_size']} bytes")
    print(f"  marker in session:     {r0['marker_present']}")
    print(f"  content preview:       {r0['sess_content'][:120]!r}")
    print()

    # -- Same with cleanup=1 (stock) --
    print("--- Test 1+2b: same with stock cleanup=1 ---")
    r1 = check_form_sid(a.php_cli, www, sess, cleanup=1)
    print(f"  session file created:  {r1['sess_created']}")
    print(f"  session file size:     {r1['sess_size']} bytes")
    print(f"  marker in session:     {r1['marker_present']}")
    print()

    # -- Test 3: does the poisoning payload land in the session file? --
    print("--- Test 3: serialized payload lands in session file ---")
    # write a poisoned session directly (worst case: attacker controls the file)
    poisoned = os.path.join(sess, "sess_poison_test")
    with open(poisoned, "w") as f:
        f.write('upload_progress_<?php system($_GET["c"]); ?>|a:0:{}\n')
    with open(poisoned, "rb") as f:
        pcontent = f.read()
    print(f"  poisoned file written: {len(pcontent)} bytes")
    print(f"  PHP open tag present:  {b'<?php' in pcontent}")
    print(f"  (this is what an LFI/include sink would execute)")
    print()

    # -- Test 4: handler mismatch --
    print("--- Test 4: handler mismatch (php_serialize data read by php handler) ---")
    r4 = check_handler_mismatch(a.php_cli, www, sess)
    print(f"  destructive decode:    {r4['destructive_decode']}")
    print(f"  response:              {r4['response'][:200]!r}")
    print()

    # -- Verdict --
    print("=" * 60)
    exposed = []
    if r0["sess_created"] and r0["marker_present"]:
        exposed.append("form-SID + progress-key persistence (cleanup=0): "
                       "attacker can plant controlled content in a known session file")
    if r4["destructive_decode"]:
        exposed.append("handler mismatch: php handler destructively decodes "
                       "php_serialize data (__destruct may fire)")

    if exposed:
        print("VERDICT: SURFACE EXPOSED — the post-patch attack surface is live:")
        for e in exposed:
            print(f"  • {e}")
        print()
        print("MITIGATION:")
        print("  session.upload_progress.enabled = 0   (kills the surface at the root)")
        print("  session.upload_progress.cleanup = 1   (limits persistence to request lifetime)")
        print("  — and ensure no application include/LFI/unserialize sink is reachable")
        print("    from session-controlled paths.")
        return 1
    if r0["sess_created"]:
        print("VERDICT: PARTIALLY EXPOSED — form-SID accepted but progress-key "
              "does not persist with stock cleanup=1. Risk is lower but the "
              "in-session-race window remains. Consider upload_progress=0.")
        return 1
    print("VERDICT: SURFACE MITIGATED — upload_progress disabled or form-SID "
          "not ingested. The post-patch chain cannot establish a foothold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
