#!/usr/bin/env python3
# ------------------------------------------------------------------------
# CyberOK — PHP-UP-2026 wave 2 defense tools (PHP security release 2026-11-19)
# (c) 2026 АО «Сайбер ОК» / JSC CyberOK — provided for informational and research purposes
# only; see the kit LICENSE / header of the rule files for the full terms.
# ------------------------------------------------------------------------
"""
host-hunt: code / config triage for the parser / client-side CVEs of the 2026-11-19 PHP release.
The right detector for these bugs is the application's own code, not the network:

  W2-128064-SCHEME        high   literal "HTTPS://", "httpS://", "FTPS://" ... (final 'S' upper-
                                 case) in PHP code or config. On PHP < 8.2.36/8.3.37/8.4.28/8.5.13
                                 the stream wrappers send such requests in CLEARTEXT (and to port
                                 80/21 when no port is given). "HTTPs://" is NOT affected (the old
                                 code tested only scheme[4]=='s' / scheme[3]=='s').
  W2-129506-SOAPSERVER    medium SoapServer::handle() called WITHOUT an argument: the php://input
                                 path (soap_xmlParseFile) that frees the DTD -> UAF + DTD-check
                                 bypass. handle($xml) uses the in-memory parser and is not affected.
  W2-129506-SOAPCLIENT    low    new SoapClient(<non-literal WSDL>): WSDL/schema parsed with the
                                 affected soap_xmlParseFile() path; check where the WSDL comes from.
  W2-129501-DOM-SAVEXML   medium modern DOM (Dom\\HTMLDocument / Dom\\XMLDocument) + saveXml() in the
                                 same file (8.4/8.5 double free when the document is attacker-shaped).
  W2-129438-URI-RFC3986   info   Uri\\Rfc3986\\Uri use (8.5): enforce a byte-length limit on input.
  W2-127960-FETCH-USER    low    file_get_contents()/fopen() fed directly from $_GET/$_POST/$_REQUEST
                                 (attacker-chosen URL -> malicious response headers / redirects).

Read-only, stdlib only. usage: php_wave2_code_hunt.py [--json] [--min info|low|medium|high] PATH...
exit: 0 nothing at/above --min (default low), 1 findings, 2 error
"""
import argparse
import json
import os
import re
import sys

CODE_EXT = (".php", ".phtml", ".inc", ".module", ".phpt", ".ctp", ".tpl.php")
CONF_EXT = (".ini", ".env", ".yaml", ".yml", ".json", ".xml", ".conf", ".neon", ".dist", ".cnf", ".properties", ".toml")
CONF_NAMES = (".env", ".env.local", ".env.production", "php.ini")
SKIP_DIRS = {".git", "node_modules", ".svn", ".hg", "__pycache__"}
SEV = {"info": 0, "low": 1, "medium": 2, "high": 3}
MAX_BYTES = 8 * 1024 * 1024

# final 'S' must be upper-case; the rest of the scheme in any case
SCHEME_RE = re.compile(r"(?<![A-Za-z0-9+.\-])((?:[Hh][Tt][Tt][Pp]|[Ff][Tt][Pp])S)://")
SOAPSERVER_RE = re.compile(r"new\s+\\?SoapServer\s*\(", re.I)
HANDLE_NOARG_RE = re.compile(r"->\s*handle\s*\(\s*\)", re.I)
HANDLE_ARG_RE = re.compile(r"->\s*handle\s*\(\s*[^)\s]", re.I)
SOAPCLIENT_RE = re.compile(r"new\s+\\?SoapClient\s*\(\s*(?!['\"]|null\b|NULL\b)", re.I)
MODERN_DOM_RE = re.compile(r"\\?Dom\\(?:HTMLDocument|XMLDocument)\b")
SAVEXML_RE = re.compile(r"->\s*saveXml\s*\(", re.I)
URI_RE = re.compile(r"\\?Uri\\Rfc3986\\Uri\b")
FETCH_USER_RE = re.compile(r"\b(?:file_get_contents|fopen|get_headers|getimagesize|copy)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b", re.I)


def is_code(name):
    return name.lower().endswith(CODE_EXT)


def is_conf(name):
    n = name.lower()
    return n.endswith(CONF_EXT) or n in CONF_NAMES or n.startswith(".env")


def finding(rule, sev, path, lineno, line, why):
    return {"rule": rule, "severity": sev, "file": path, "line": lineno, "snippet": line.strip()[:200], "why": why}


def scan_text(path, text, code):
    out = []
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        for m in SCHEME_RE.finditer(line):
            out.append(finding("W2-128064-SCHEME", "high", path, i, line,
                               "scheme '%s://' is sent in cleartext by unpatched PHP stream wrappers (CVE-2026-128064)" % m.group(1)))
    if not code:
        return out
    has_server = bool(SOAPSERVER_RE.search(text))
    has_dom = bool(MODERN_DOM_RE.search(text))
    for i, line in enumerate(lines, 1):
        if has_server and HANDLE_NOARG_RE.search(line):
            out.append(finding("W2-129506-SOAPSERVER", "medium", path, i, line,
                               "SoapServer::handle() without argument parses php://input via soap_xmlParseFile (CVE-2026-129506 UAF path)"))
        elif has_server and HANDLE_ARG_RE.search(line):
            out.append(finding("W2-129506-SOAPSERVER-ARG", "info", path, i, line,
                               "handle($xml) uses the in-memory parser: DTD check intact, request UAF path not reached"))
        if SOAPCLIENT_RE.search(line):
            out.append(finding("W2-129506-SOAPCLIENT", "low", path, i, line,
                               "SoapClient WSDL from a non-literal source: WSDL/schema DTD UAF path (CVE-2026-129506)"))
        if has_dom and SAVEXML_RE.search(line):
            out.append(finding("W2-129501-DOM-SAVEXML", "medium", path, i, line,
                               "modern DOM saveXml(): XML serializer double free on 8.4/8.5 (CVE-2026-129501)"))
        if URI_RE.search(line):
            out.append(finding("W2-129438-URI-RFC3986", "info", path, i, line,
                               "Uri\\Rfc3986\\Uri: cap input length well below 2 GiB (CVE-2026-129438, 8.5)"))
        if FETCH_USER_RE.search(line):
            out.append(finding("W2-127960-FETCH-USER", "low", path, i, line,
                               "URL fetched straight from request input: malicious response headers (CVE-2026-127960) / redirects"))
    return out


def iter_files(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
            continue
        for root, dirs, files in os.walk(p):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for f in files:
                if is_code(f) or is_conf(f):
                    yield os.path.join(root, f)


def scan(paths):
    results = []
    for f in iter_files(paths):
        try:
            if os.path.getsize(f) > MAX_BYTES:
                continue
            with open(f, "rb") as fh:
                text = fh.read().decode("utf-8", "replace")
        except OSError:
            continue
        results.extend(scan_text(f, text, is_code(os.path.basename(f))))
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(description="PHP-UP-2026-W2 parser/client-side code/config triage (read-only)")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--min", default="low", choices=list(SEV))
    a = ap.parse_args(argv)
    res = [r for r in scan(a.paths) if SEV[r["severity"]] >= SEV[a.min]]
    if a.json:
        print(json.dumps({"findings": res, "count": len(res)}, indent=2))
    else:
        for r in res:
            print("%-6s %-26s %s:%d  %s" % (r["severity"].upper(), r["rule"], r["file"], r["line"], r["snippet"][:100]))
        print("findings=%d" % len(res), file=sys.stderr)
    return 1 if res else 0


if __name__ == "__main__":
    sys.exit(main())
