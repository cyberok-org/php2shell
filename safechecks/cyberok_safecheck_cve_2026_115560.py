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
SAFECHECK: CVE-2026-115560 — RCE via session serializer handler mismatch.

This CVE is NOT fixed by the 2026-10-21 releases (8.2.35/8.3.36/8.4.27/8.5.12).
It requires a COMBINATION of conditions:
  1. session.serialize_handler is set to php_binary or php_serialize
     in the server configuration
  2. The APPLICATION switches it to 'php' via ini_set() before session_start()
  3. session.upload_progress.enabled is 1 (default)

The attack: a crafted PHP_SESSION_UPLOAD_PROGRESS value containing a pipe-
separated serialized object is stored under the php_serialize handler.
When the application switches to the 'php' handler and calls session_start(),
the decoder splits at the pipe and unserializes the object, firing __destruct().

This safecheck tests the TWO server-side conditions (1 and 3) by reading the
effective php.ini configuration. Condition 2 (application code) cannot be
tested from the server config alone.

Usage:
  python3 cyberok_safecheck_cve_2026_115560.py --php-cli /path/to/php
  python3 cyberok_safecheck_cve_2026_115560.py --ini /path/to/php.ini

Exit:  0 = conditions not met, 1 = conditions met (surface exposed), 2 = inconclusive
"""
import argparse
import os
import re
import subprocess
import sys


def get_ini_value(php_cli, directive, php_ini=None):
    """Read the effective ini value for a directive."""
    cmd = [php_cli, "-r", f"echo ini_get('{directive}');"]
    if php_ini:
        cmd = [php_cli, "-c", php_ini, "-r", f"echo ini_get('{directive}');"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.stdout.strip()
    except Exception:
        return None


def check_config(php_cli, php_ini=None):
    """Check the two server-side preconditions for CVE-2026-115560."""
    print("=== CVE-2026-115560: Serializer Mismatch Preconditions ===\n")

    results = {}

    # Condition 1: serialize_handler is php_binary or php_serialize
    handler = get_ini_value(php_cli, "session.serialize_handler", php_ini)
    results["serialize_handler"] = handler
    print(f"  session.serialize_handler = {handler!r}")
    handler_vulnerable = handler in ("php_binary", "php_serialize", "")
    if handler == "":
        print("    → EMPTY (will use php_serialize default in PHP 7.0+)")
        handler_vulnerable = True
    elif handler == "php":
        print("    → 'php' (default): NOT vulnerable to this specific mismatch")
        handler_vulnerable = False
    elif handler_vulnerable:
        print(f"    → '{handler}': VULNERABLE precondition met")
    else:
        print(f"    → '{handler}': unknown handler")

    # Condition 3: upload_progress.enabled
    progress = get_ini_value(php_cli, "session.upload_progress.enabled", php_ini)
    results["upload_progress_enabled"] = progress
    print(f"  session.upload_progress.enabled = {progress!r}")
    progress_enabled = progress in ("1", "On", "on", "true", "")
    if progress_enabled:
        print("    → ENABLED: VULNERABLE precondition met")
    else:
        print("    → DISABLED: surface closed")

    # Additional context
    cleanup = get_ini_value(php_cli, "session.upload_progress.cleanup", php_ini)
    results["cleanup"] = cleanup
    print(f"  session.upload_progress.cleanup = {cleanup!r}")
    use_strict = get_ini_value(php_cli, "session.use_strict_mode", php_ini)
    results["use_strict_mode"] = use_strict
    print(f"  session.use_strict_mode = {use_strict!r}")

    # Verdict
    print("\n" + "=" * 50)
    if progress == "0" or progress == "Off" or progress == "off":
        print("VERDICT: SURFACE CLOSED — session.upload_progress.enabled=0")
        print("  The upload-progress mechanism is disabled; the poisoning")
        print("  path for CVE-2026-115560 cannot be reached.")
        return 0
    elif handler_vulnerable and progress_enabled:
        print("VERDICT: PRECONDITIONS MET — server-side surface is exposed.")
        print(f"  serialize_handler={handler!r} + upload_progress=enabled.")
        print("  The REMAINING condition is APPLICATION-side:")
        print("  the app must call ini_set('session.serialize_handler', 'php')")
        print("  before session_start(). Audit application code for this pattern.")
        print("\n  MITIGATION: session.upload_progress.enabled = 0")
        return 1
    elif not handler_vulnerable:
        print(f"VERDICT: PARTIALLY EXPOSED — upload_progress enabled but")
        print(f"  serialize_handler={handler!r} is not php_binary/php_serialize.")
        print("  Vulnerable only if the app switches handler at runtime.")
        return 0
    else:
        print("VERDICT: INCONCLUSIVE — could not read configuration.")
        return 2


def main():
    ap = argparse.ArgumentParser(
        description="CyberOK safecheck for CVE-2026-115560 (serializer mismatch)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--php-cli", help="path to PHP CLI binary (reads effective ini)")
    g.add_argument("--ini", help="path to php.ini file (static analysis)")
    a = ap.parse_args()

    if a.php_cli:
        ver = subprocess.run([a.php_cli, "-v"], capture_output=True, text=True)
        print(f"PHP: {(ver.stdout or '?').splitlines()[0]}")
        print()
        return check_config(a.php_cli)

    if a.ini:
        if not os.path.exists(a.ini):
            print(f"ERROR: file not found: {a.ini}", file=sys.stderr)
            return 2
        print(f"php.ini: {a.ini}")
        print()
        # Static analysis: grep the ini file for relevant directives
        handler = None
        progress = None
        with open(a.ini) as f:
            for line in f:
                line = line.strip()
                if line.startswith("session.serialize_handler"):
                    handler = line.split("=", 1)[1].strip().strip("'\"")
                elif line.startswith("session.upload_progress.enabled"):
                    progress = line.split("=", 1)[1].strip().strip("'\"")

        print(f"  session.serialize_handler = {handler!r}")
        print(f"  session.upload_progress.enabled = {progress!r}")

        if progress in ("0", "Off", "off"):
            print("\nVERDICT: SURFACE CLOSED (upload_progress disabled)")
            return 0
        elif handler in ("php_binary", "php_serialize") and progress != "0":
            print("\nVERDICT: PRECONDITIONS MET (audit app code for ini_set)")
            return 1
        else:
            print("\nVERDICT: check application code for runtime handler switch")
            return 0


if __name__ == "__main__":
    sys.exit(main())
