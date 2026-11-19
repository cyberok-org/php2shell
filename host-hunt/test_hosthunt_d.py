#!/usr/bin/env python3
"""Regression tests for the wave-2 host-hunt scanners (code hunt, phar pubkey scan) (stdlib unittest).
run: python3 -m unittest -v test_hosthunt_d.py   (from host-hunt/)"""
import os
import shutil
import struct
import tempfile
import unittest

import phar_pubkey_scan as pps
import php_wave2_code_hunt as hunt

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures", "phar")


class CodeHunt(unittest.TestCase):
    def rules(self, text, name="x.php"):
        return sorted({r["rule"] for r in hunt.scan_text(name, text, hunt.is_code(name))})

    def test_scheme_positive(self):
        for s in ("HTTPS://api.example/", "httpS://a/", "HttpS://a", "FTPS://u:p@h/f", "ftpS://h/"):
            self.assertEqual(self.rules("<?php $u = '%s';" % s), ["W2-128064-SCHEME"], s)

    def test_scheme_negative(self):
        for s in ("https://a/", "HTTPs://a/", "httPs://a", "ftps://h/", "FTPs://h/", "http://a/", "xhttpS://a", "SFTPS://a"):
            self.assertEqual(self.rules("<?php $u = '%s';" % s), [], s)

    def test_scheme_in_config(self):
        self.assertEqual(self.rules("API_URL=HTTPS://pay.example/v1\n", ".env"), ["W2-128064-SCHEME"])
        self.assertEqual(self.rules("API_URL=https://pay.example/v1\n", ".env"), [])

    def test_soapserver(self):
        self.assertEqual(self.rules("<?php $s = new SoapServer(null, []); $s->handle();"), ["W2-129506-SOAPSERVER"])
        self.assertEqual(self.rules("<?php $s = new \\SoapServer('a.wsdl'); $s->handle(file_get_contents('php://input'));"),
                         ["W2-129506-SOAPSERVER-ARG"])
        self.assertEqual(self.rules("<?php $job->handle();"), [])          # no SoapServer in file

    def test_soapclient(self):
        self.assertEqual(self.rules("<?php $c = new SoapClient($wsdlUrl);"), ["W2-129506-SOAPCLIENT"])
        self.assertEqual(self.rules("<?php $c = new SoapClient('local.wsdl');"), [])
        self.assertEqual(self.rules("<?php $c = new SoapClient(null, ['location'=>$x]);"), [])

    def test_dom(self):
        self.assertEqual(self.rules("<?php $d = Dom\\HTMLDocument::createFromString($h); echo $d->saveXml();"),
                         ["W2-129501-DOM-SAVEXML"])
        self.assertEqual(self.rules("<?php $d = new DOMDocument(); echo $d->saveXML();"), [])   # legacy DOM unaffected

    def test_uri_and_fetch(self):
        self.assertIn("W2-129438-URI-RFC3986", self.rules("<?php $u = new Uri\\Rfc3986\\Uri($in);"))
        self.assertEqual(self.rules("<?php echo file_get_contents($_GET['u']);"), ["W2-127960-FETCH-USER"])

    def test_exit_codes(self):
        d = tempfile.mkdtemp()
        try:
            open(os.path.join(d, "a.php"), "w").write("<?php $u='https://ok/';")
            self.assertEqual(hunt.main([d]), 0)
            open(os.path.join(d, "b.php"), "w").write("<?php $u='HTTPS://bad/';")
            self.assertEqual(hunt.main([d]), 1)
        finally:
            shutil.rmtree(d)


class PharScan(unittest.TestCase):
    def status(self, name):
        return pps.scan_file(os.path.join(FIX, name))

    def test_lab_fixtures(self):
        # built in the lab with PHP 8.2.35: OpenSSL-signed originals and keyless SHA-256 downgrades
        for fmt in ("phar", "phar.tar", "phar.zip"):
            ok, bad = self.status("app-signed." + fmt), self.status("app-tampered." + fmt)
            self.assertEqual((ok["status"], ok["signature"]), ("OK", "OpenSSL"), fmt)
            self.assertEqual((bad["status"], bad["signature"]), ("FLAG", "SHA-256"), fmt)

    def test_no_pubkey_is_info(self):
        d = tempfile.mkdtemp()
        try:
            shutil.copy(os.path.join(FIX, "app-tampered.phar"), os.path.join(d, "x.phar"))
            self.assertEqual(pps.scan_file(os.path.join(d, "x.phar"))["status"], "INFO-no-pubkey")
            open(os.path.join(d, "x.phar.pubkey"), "w").write("k")
            self.assertEqual(pps.scan_file(os.path.join(d, "x.phar"))["status"], "FLAG")
        finally:
            shutil.rmtree(d)

    def test_synthetic_native_trailers(self):
        d = tempfile.mkdtemp()
        try:
            for flags, expect in ((0x0010, "OK"), (0x0011, "OK"), (0x0012, "OK"), (0x0001, "FLAG"), (0x0002, "FLAG"),
                                  (0x0003, "FLAG"), (0x0004, "FLAG")):
                p = os.path.join(d, "s%d.phar" % flags)
                open(p, "wb").write(b"<?php __HALT_COMPILER(); ?>\r\n" + b"\0" * 40 + struct.pack("<I", flags) + b"GBMB")
                open(p + ".pubkey", "w").write("k")
                self.assertEqual(pps.scan_file(p)["status"], expect, hex(flags))
            self.assertEqual(pps.main([d]), 1)
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
