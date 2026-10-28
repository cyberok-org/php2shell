"""Offline synthetic regression tests. Fixtures are bytes; PHP is never run."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yara
import hosthunt

ROOT = Path(__file__).parent
RULE_TEXT = (ROOT / 'php2shell_hosthunt.yar').read_text()
RULES = yara.compile(source=RULE_TEXT, externals={'scope': 'unscoped', 'filename': ''})
DIRECT = b'<?php\nsystem($_GET['  # deliberately incomplete PHP, never executed
PREFIX = 'PHP2SHELL_'


def matches(data, scope='session', filename='sess_review'):
    return {m.rule for m in RULES.match(data=data, externals={'scope': scope, 'filename': filename})}


class RuleTests(unittest.TestCase):
    def test_all_rules_compile_without_warnings(self):
        self.assertEqual(len(list(RULES)), 7)
        self.assertEqual(RULES.warnings, [])

    def test_normal_session_array_and_object_do_not_match(self):
        self.assertFalse(matches(b'user|a:1:{s:2:"id";i:2;}profile|O:7:"Profile":0:{}'))

    def test_normal_upload_progress_does_not_match(self):
        self.assertFalse(matches(b'upload_progress_123|a:2:{s:8:"filename";s:5:"a.txt";s:4:"done";b:1;}'))

    def test_php_tag_without_progress_is_not_poisoning_rule(self):
        self.assertFalse(matches(b'snippet|s:22:"<?php echo 1; ?>";'))

    def test_php_in_progress_is_stored_input_not_execution(self):
        found = matches(b'upload_progress_example|a:1:{<?php /* harmless snippet */}')
        self.assertEqual(found, {PREFIX + 'Session_UploadProgress_PHP'})

    def test_object_seed_needs_progress_context(self):
        self.assertIn(PREFIX+'Session_Progress_ObjectSeed', matches(b'upload_progress_inj|O:6:"Review":0:{}'))
        self.assertFalse(matches(b'profile|O:6:"Review":0:{}'))

    def test_missing_progress_prefix_is_documented_limit(self):
        self.assertFalse(matches(b'custom_prefix_inj|O:6:"Review":0:{}'))

    def test_progress_array_then_legitimate_object_does_not_match(self):
        self.assertFalse(matches(b'upload_progress_123|a:0:{}cart|O:8:"stdClass":0:{}'))

    def test_exact_poc_filename_needs_code(self):
        self.assertFalse(matches(b'not PHP', 'web', 'p2s_8512_shell.php'))
        found = matches(DIRECT, 'web', 'p2s_8512_shell.php')
        self.assertIn(PREFIX+'PublicPoC_8512_Named_Shell', found)
        self.assertIn('PHP_Direct_Request_Execution_Heuristic', found)

    def test_renamed_shell_only_generic(self):
        self.assertEqual(matches(DIRECT, 'web', 'renamed.php'), {'PHP_Direct_Request_Execution_Heuristic'})

    def test_ordinary_echo_or_constant_system_call_do_not_match(self):
        self.assertFalse(matches(b'<?php echo $_GET["name"];', 'web', 'index.php'))
        self.assertFalse(matches(b'<?php system("date");', 'web', 'index.php'))

    def test_session_poc_both_markers_required(self):
        fixture = b'<?php SHELL_ALIVE PAYLOAD_PERSISTED sid= shell_exec'
        self.assertEqual(matches(fixture), {PREFIX+'PublicPoC_Session_Webshell'})
        self.assertFalse(matches(fixture.replace(b'PAYLOAD_PERSISTED sid=', b'')))

    def test_capture_sequence_order_spacing_and_scope(self):
        fixture = b'i:4294967296;i:8589934592;i:12884901888;'
        self.assertEqual(matches(fixture, 'capture', 'body.bin'), {PREFIX+'Captured_Integer_Key_Sequence'})
        self.assertFalse(matches(fixture, 'web', 'data.bin'))
        self.assertFalse(matches(b'i:8589934592;i:4294967296;i:12884901888;', 'capture'))
        self.assertFalse(matches(b'i:4294967296;' + b'x'*49 + b'i:8589934592;i:12884901888;', 'capture'))

    def test_test_marker_does_not_suppress(self):
        fixture = b'upload_progress_cyberok_test|<?php ZZ_POSTPATCH_MARKER'
        self.assertIn(PREFIX+'Session_UploadProgress_PHP', matches(fixture))

    def test_hash_rule_pipeline_with_benign_digest_substitution(self):
        # Only a copy of the rule source is changed in memory. No malware
        # downloaded; validates hash-module plumbing, not real-sample accuracy.
        data = b'benign fixture for exact-hash logic\n'
        substitute = RULE_TEXT.replace(
            '4d02f14d109458cb0d696b65456918fcd724ca385aa30c688f08554c8899938c',
            hashlib.sha256(data).hexdigest())
        rule = yara.compile(source=substitute, externals={'scope':'unscoped','filename':''})
        self.assertEqual({m.rule for m in rule.match(data=data)}, {PREFIX+'Associated_Malware_Exact_SHA256'})
        self.assertFalse(matches(data, 'artifact'))

    def test_ioc_hash_list_agrees_with_rules(self):
        iocs = json.loads((ROOT/'iocs.json').read_text())
        for row in iocs['file_sha256']:
            self.assertEqual(len(row['sha256']), 64)
            int(row['sha256'], 16)
            self.assertIn(row['sha256'], RULE_TEXT)


class RunnerTests(unittest.TestCase):
    def run_hunt(self, args):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = hosthunt.run(args)
        rows = [json.loads(line) for line in stream.getvalue().splitlines()]
        return code, rows

    def test_clean_scope_result_not_clean_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'index.php').write_bytes(b'<?php echo "hello";')
            code, rows = self.run_hunt(['--webroot', tmp])
        self.assertEqual(code, 0)
        self.assertEqual(rows[-1]['verdict'], 'NO_MATCH_IN_SCANNED_SCOPE')

    def test_findings_contain_metadata_not_session_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'sess_test').write_bytes(b'upload_progress_test|<?php SECRET_USER_TOKEN cyberok_test')
            code, rows = self.run_hunt(['--session-dir', tmp])
        self.assertEqual(code, 1)
        self.assertNotIn('SECRET_USER_TOKEN', json.dumps(rows))
        self.assertEqual(rows[-1]['matched_files'], 1)
        found = next(r for r in rows if r['type']=='finding')
        self.assertEqual(found['known_test_markers_present'], ['cyberok_test'])

    def test_missing_or_empty_root_returns_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            for path in (tmp, str(Path(tmp)/'missing')):
                code, rows = self.run_hunt(['--webroot', path])
                self.assertEqual(code, 2)
                self.assertTrue(rows[-1]['incomplete'])

    def test_oversize_symlink_archive_not_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'large').write_bytes(b'x'*20)
            Path(tmp, 'small').write_bytes(b'ok')
            Path(tmp, 'copy.gz').write_bytes(b'x')
            Path(tmp, 'link').symlink_to(Path(tmp, 'small'))
            code, rows = self.run_hunt(['--artifact-dir', tmp, '--max-bytes', '10'])
        self.assertEqual(code, 2)
        self.assertEqual(rows[-1]['scanned'], 1)
        self.assertEqual(rows[-1]['skipped'], 3)

    def test_hit_plus_partial_keeps_both_signals(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'p2s_8512_shell.php').write_bytes(DIRECT)
            code, rows = self.run_hunt(['--webroot', tmp, '--artifact-dir', str(Path(tmp)/'missing')])
        self.assertEqual(code, 1)
        self.assertTrue(rows[-1]['incomplete'])

    def test_only_sess_files_in_session_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'other').write_bytes(b'upload_progress_|<?php')
            Path(tmp, 'sess_ok').write_bytes(b'user|i:1;')
            code, rows = self.run_hunt(['--session-dir', tmp])
        self.assertEqual(code, 0)
        self.assertEqual(rows[-1]['excluded_by_scope'], 1)

    def test_externals_updated_for_each_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ('p2s_8512_shell.php','different.php'):
                Path(tmp, name).write_bytes(DIRECT)
            code, rows = self.run_hunt(['--webroot', tmp])
        findings = {Path(r['path']).name:{x['rule'] for x in r['matches']} for r in rows if r['type']=='finding'}
        self.assertIn(PREFIX+'PublicPoC_8512_Named_Shell', findings['p2s_8512_shell.php'])
        self.assertNotIn(PREFIX+'PublicPoC_8512_Named_Shell', findings['different.php'])

    def test_overlapping_roots_do_not_report_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            child = Path(tmp, 'child')
            child.mkdir()
            (child/'index.php').write_bytes(b'<?php echo "hello";')
            code, rows = self.run_hunt(['--webroot', tmp, '--webroot', str(child)])
        self.assertEqual(code, 0)
        self.assertEqual(rows[-1]['scanned'], 1)

    def test_permission_error_is_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'index.php').write_bytes(b'hello')
            with patch.object(hosthunt.os, 'open', side_effect=PermissionError('fixture access denied')):
                code, rows = self.run_hunt(['--webroot', tmp])
        self.assertEqual(code, 2)
        self.assertEqual(rows[-1]['errors'], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
