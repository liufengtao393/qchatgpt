"""Unit tests for log_scan hard-gate exit codes, allowlist, and workflow wiring."""

import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

from tools.entrypoints import log_scan


ROOT = Path(__file__).resolve().parents[2]
INFO_LINE = (
    '[2026-11-28 14:15:15.582985+00:00] INFO  [CORE.APP] start (app.py:10) [100][MainThread/Task-1][ws=-][-] Ready'
)
WARN_LINE = (
    '[2026-11-28 14:15:15.582985+00:00] WARN  [CORE.PIPELINE] finish_query (monitoring_helper.py:336) '
    '[100][MainThread/query-1][ws=test][Y-abc] Terminal monitoring write failed (attempt 1): TimeoutError()'
)
ERROR_LINE = (
    '[2026-11-28 14:15:15.582985+00:00] ERROR [CORE.PIPELINE] query (mgr.py:312) '
    '[100][MainThread/job][ws=test][Y-abc] RuntimeError: unhandled failure'
)
FATAL_LINE = (
    '[2026-11-28 14:15:15.582985+00:00] CRITICAL [CORE.APP] boot (app.py:99) '
    '[100][MainThread/job][ws=-][-] fatal boot crash'
)
HTTP_500_LINE = (
    '[2026-11-28 14:15:15.582985+00:00] INFO  [CORE.HTTP] access (logging.py:89) '
    '[100][MainThread/Task-1][ws=test][Y-abc] 127.0.0.1:35196 GET /api/v1/pipelines/123 1.1 500 12 34'
)
EMPTY_EXC_LINE = (
    '[2026-11-28 14:15:15.582985+00:00] ERROR [CORE.PIPELINE] finish_query (monitoring_helper.py:336) '
    '[100][MainThread/query-1][ws=test][Y-abc] Terminal monitoring write failed (attempt 1): '
)
BARE_TRACEBACK = '\n'.join(
    [
        INFO_LINE,
        'Traceback (most recent call last):',
        '  File "core.py", line 42, in run',
        '    raise RuntimeError("boom")',
        'RuntimeError: boom',
    ]
)
LOGGED_TRACEBACK = '\n'.join(
    [
        ERROR_LINE,
        '\tTraceback (most recent call last):',
        '\t  File "mgr.py", line 312, in query',
        '\tRuntimeError: unhandled failure',
    ]
)


class LogScanHardGateTests(unittest.TestCase):
    def _run_main(self, argv):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            rc = log_scan.main(argv)
        return rc, stdout.getvalue(), stderr.getvalue()

    def test_missing_input_logs_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            allow = root / 'allow.yaml'
            allow.write_text('[]\n', encoding='utf-8')
            argv = [
                '--input',
                str(root / 'does-not-exist-*.log'),
                '--allowlist',
                str(allow),
                '--output',
                str(root / 'out'),
            ]
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as ctx:
                log_scan.main(argv)
            self.assertEqual(ctx.exception.code, 2)
            self.assertIn('no input logs matched', stderr.getvalue())

            proc = subprocess.run(
                [sys.executable, '-m', 'tools.entrypoints.log_scan', *argv],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn('no input logs matched', proc.stderr)

    def test_directory_match_does_not_count_as_input_log(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fake_log_dir = root / 'core.log'
            fake_log_dir.mkdir()
            allow = root / 'allow.yaml'
            allow.write_text('[]\n', encoding='utf-8')
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as ctx:
                log_scan.main(
                    [
                        '--input',
                        str(root / '*.log'),
                        '--allowlist',
                        str(allow),
                        '--output',
                        str(root / 'out'),
                    ]
                )
            self.assertEqual(ctx.exception.code, 2)
            self.assertIn('no input logs matched', stderr.getvalue())

    def test_missing_allowlist_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            log_file = root / 'core.log'
            log_file.write_text(INFO_LINE + '\n', encoding='utf-8')
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as ctx:
                log_scan.main(
                    [
                        '--input',
                        str(log_file),
                        '--allowlist',
                        str(root / 'missing.yaml'),
                        '--output',
                        str(root / 'out'),
                    ]
                )
            self.assertEqual(ctx.exception.code, 2)
            self.assertIn('allowlist file not found', stderr.getvalue())

    def test_blocking_anomalies_fail_by_default_and_write_reports(self):
        cases = [
            ('error', ERROR_LINE),
            ('fatal', FATAL_LINE),
            ('bare_traceback', BARE_TRACEBACK),
            ('logged_traceback', LOGGED_TRACEBACK),
            ('http_5xx', HTTP_500_LINE),
            ('empty_exception_message', EMPTY_EXC_LINE),
        ]
        for label, content in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                log_file = root / 'core.log'
                log_file.write_text(content + '\n', encoding='utf-8')
                allow = root / 'allow.yaml'
                allow.write_text('[]\n', encoding='utf-8')
                out = root / 'out'
                rc, _, err = self._run_main(['--input', str(log_file), '--allowlist', str(allow), '--output', str(out)])
                self.assertEqual(rc, 1)
                self.assertIn('log_scan: FAIL', err)
                report = json.loads((out / 'log-anomalies.json').read_text(encoding='utf-8'))
                self.assertFalse(report['gate']['passed'])
                self.assertEqual(report['gate']['mode'], 'default')
                self.assertGreaterEqual(report['gate']['blocking_count'], 1)
                md = (out / 'log-anomalies.md').read_text(encoding='utf-8')
                self.assertIn('Gate: **FAIL**', md)

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            log_file = root / 'core.log'
            log_file.write_text(BARE_TRACEBACK + '\n', encoding='utf-8')
            allow = root / 'allow.yaml'
            allow.write_text('[]\n', encoding='utf-8')
            proc = subprocess.run(
                [
                    sys.executable,
                    '-m',
                    'tools.entrypoints.log_scan',
                    '--input',
                    str(log_file),
                    '--allowlist',
                    str(allow),
                    '--output',
                    str(root / 'out'),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn('log_scan: FAIL', proc.stderr)
            self.assertIn('[traceback]', proc.stderr)

    def test_allowlisted_error_respects_max_count(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            log_file = root / 'core.log'
            allow = root / 'allow.yaml'
            allow.write_text(
                yaml.safe_dump(
                    [
                        {
                            'pattern': 'core|CORE.PIPELINE|query|RuntimeError|RuntimeError: unhandled failure',
                            'reason': 'Controlled unit test fixture.',
                            'max_count': 1,
                        }
                    ]
                ),
                encoding='utf-8',
            )
            log_file.write_text(ERROR_LINE + '\n', encoding='utf-8')
            rc_ok, out_ok, _ = self._run_main(
                ['--input', str(log_file), '--allowlist', str(allow), '--output', str(root / 'ok')]
            )
            self.assertEqual(rc_ok, 0)
            self.assertIn('log_scan: PASS', out_ok)

            log_file.write_text(ERROR_LINE + '\n' + ERROR_LINE + '\n', encoding='utf-8')
            rc_fail, _, err_fail = self._run_main(
                ['--input', str(log_file), '--allowlist', str(allow), '--output', str(root / 'fail')]
            )
            self.assertEqual(rc_fail, 1)
            self.assertIn('log_scan: FAIL', err_fail)

    def test_warn_and_unparsed_ratio_pass_by_default_and_fail_in_strict_mode(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            log_file = root / 'core.log'
            log_file.write_text(WARN_LINE + '\nunparsed banner line\n', encoding='utf-8')
            allow = root / 'allow.yaml'
            allow.write_text('[]\n', encoding='utf-8')

            rc_default, out_default, _ = self._run_main(
                ['--input', str(log_file), '--allowlist', str(allow), '--output', str(root / 'default')]
            )
            self.assertEqual(rc_default, 0)
            self.assertIn('log_scan: PASS', out_default)
            default_report = json.loads((root / 'default/log-anomalies.json').read_text(encoding='utf-8'))
            self.assertTrue(default_report['gate']['passed'])
            self.assertEqual(default_report['gate']['blocking_count'], 0)
            self.assertEqual(default_report['gate']['total_anomalies'], 2)

            rc_strict, _, err_strict = self._run_main(
                [
                    '--input',
                    str(log_file),
                    '--allowlist',
                    str(allow),
                    '--output',
                    str(root / 'strict'),
                    '--strict',
                ]
            )
            self.assertEqual(rc_strict, 1)
            self.assertIn('log_scan: FAIL', err_strict)
            strict_report = json.loads((root / 'strict/log-anomalies.json').read_text(encoding='utf-8'))
            self.assertFalse(strict_report['gate']['passed'])
            self.assertEqual(strict_report['gate']['mode'], 'strict')
            self.assertEqual(strict_report['gate']['blocking_count'], 2)

    def test_clean_log_passes_in_strict_mode(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            log_file = root / 'core.log'
            log_file.write_text(INFO_LINE + '\n', encoding='utf-8')
            allow = root / 'allow.yaml'
            allow.write_text('[]\n', encoding='utf-8')
            rc, out, _ = self._run_main(
                ['--input', str(log_file), '--allowlist', str(allow), '--output', str(root / 'out'), '--strict']
            )
            self.assertEqual(rc, 0)
            self.assertIn('log_scan: PASS', out)

    def test_checked_in_allowlist_is_valid_and_guards_persistence_negative_case(self):
        allowlist_path = ROOT / 'tools/log_scan_allowlist.yaml'
        rules = yaml.safe_load(allowlist_path.read_text(encoding='utf-8'))
        self.assertIsInstance(rules, list)
        self.assertGreater(len(rules), 0)
        for rule in rules:
            self.assertIsInstance(rule, dict)
            self.assertTrue(isinstance(rule.get('pattern'), str) and rule['pattern'].strip())
            self.assertTrue(isinstance(rule.get('reason'), str) and rule['reason'].strip())
            self.assertIsInstance(rule.get('max_count'), int)
            self.assertGreater(rule['max_count'], 0)
            self.assertNotIn('Terminal monitoring write failed', rule['pattern'])

        expected_persistence_tb = '\n'.join(
            [
                '[2026-11-28 14:16:29.864766+00:00] ERROR [CORE.PLUGIN] call_tool (handler.py:2133) '
                '[8906][MainThread/Task-375][ws=c7e68f32-3529-541e-96e5-26395e38663d][Y-9bad43c5ed256775] '
                'Failed to execute tool register_skill BoxValidationError: '
                'Skill draft path must be a normalized absolute path under /workspace',
                '\tTraceback (most recent call last):',
                '\tlangbot_plugin.box.errors.BoxValidationError: '
                'Skill draft path must be a normalized absolute path under /workspace',
            ]
        )
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            log_file = root / 'langbot.stdout.log'
            log_file.write_text(INFO_LINE + '\n' + expected_persistence_tb + '\n', encoding='utf-8')
            rc_once, _, _ = self._run_main(
                [
                    '--input',
                    str(log_file),
                    '--service-map',
                    'langbot.stdout.log=core',
                    '--allowlist',
                    str(allowlist_path),
                    '--output',
                    str(root / 'once'),
                ]
            )
            self.assertEqual(rc_once, 0)

            log_file.write_text(
                INFO_LINE + '\n' + expected_persistence_tb + '\n' + expected_persistence_tb + '\n',
                encoding='utf-8',
            )
            rc_twice, _, _ = self._run_main(
                [
                    '--input',
                    str(log_file),
                    '--service-map',
                    'langbot.stdout.log=core',
                    '--allowlist',
                    str(allowlist_path),
                    '--output',
                    str(root / 'twice'),
                ]
            )
            self.assertEqual(rc_twice, 1)

    def test_persistence_acceptance_workflow_enforces_hard_log_scan_gate(self):
        workflow_path = ROOT / '.github/workflows/persistence-acceptance.yml'
        workflow = yaml.safe_load(workflow_path.read_text(encoding='utf-8'))
        steps = workflow['jobs']['persistence-runtime']['steps']
        scan_step = next(step for step in steps if step.get('name') == 'Scan persistence service logs')
        self.assertFalse(scan_step.get('continue-on-error', False))
        self.assertIn('tools.entrypoints.log_scan', scan_step['run'])
        self.assertIn('exit "$status"', scan_step['run'])
        upload_step = next(step for step in steps if step.get('name') == 'Upload persistence and Runtime evidence')
        self.assertIn('skill-network-processes/**/langbot.*.log', upload_step['with']['path'])


if __name__ == '__main__':
    unittest.main()
