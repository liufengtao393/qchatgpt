"""Self-tests for the static storage abstraction and layer boundary gate."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from textwrap import dedent
import tomllib
import unittest


SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent
GATE = SCRIPTS_DIR / 'check_storage_boundaries.py'
BASELINE_FILE = SCRIPTS_DIR / 'storage_boundaries_baseline.json'

sys.path.insert(0, str(SCRIPTS_DIR))
import check_storage_boundaries as gate  # noqa: E402


class StorageBoundaryRulesTests(unittest.TestCase):
    def test_rejects_storage_dialect_and_driver_imports_outside_persistence(self):
        src = dedent("""\
            import sqlite3
            from sqlalchemy.dialects import postgresql, sqlite
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert
        """)
        violations = gate.scan_file('src/langbot/pkg/pipeline/sample.py', src)
        rules = [(v.line, v.rule) for v in violations]
        self.assertEqual(
            rules,
            [
                (1, 'STORAGE_DIALECT_IMPORT'),
                (2, 'STORAGE_DIALECT_IMPORT'),
                (2, 'STORAGE_DIALECT_IMPORT'),
                (3, 'STORAGE_DIALECT_IMPORT'),
            ],
        )
        self.assertTrue(all('langbot.pkg.persistence' in v.guidance for v in violations))

    def test_allows_storage_imports_inside_persistence_and_pgvector(self):
        src = dedent("""\
            import sqlite3
            from sqlalchemy.dialects.postgresql import insert as pg_insert
            name = engine.dialect.name
            sql = 'SELECT * FROM sqlite_master'
            conn = ap.persistence_mgr.get_db_engine().connect()
            ts = sa.func.date_trunc('hour', col)
        """)
        self.assertEqual(gate.scan_file('src/langbot/pkg/persistence/dialect.py', src), [])
        self.assertEqual(gate.scan_file('src/langbot/pkg/vector/vdbs/pgvector_db.py', src), [])

    def test_rejects_dialect_name_raw_sql_dialect_funcs_and_split_line_engine_bypass(self):
        src = dedent("""\
            from datetime import datetime
            import sqlalchemy as sa
            from sqlalchemy import func

            def check(ap, engine):
                ok_str = datetime.now().strftime('%Y-%m-%d')
                if engine.dialect.name == 'sqlite':
                    q1 = 'SELECT name FROM sqlite_master WHERE type="table"'
                    q2 = "SELECT set_config('langbot.workspace_uuid', :w, true)"
                    q3 = 'PRAGMA busy_timeout=5000'
                    q4 = sa.func.date_trunc('hour', col)
                    q5 = func.json_extract(col, '$.a')
                    q6 = func.strftime('%Y-%m', col)
                    c1 = ap.persistence_mgr.get_db_engine().connect()
                    eng = ap.persistence_mgr.get_db_engine()
                    c2 = eng.begin()
                    return ok_str, q1, q2, q3, q4, q5, q6, c1, c2
        """)
        violations = gate.scan_file('src/langbot/pkg/command/sample.py', src)
        self.assertEqual(
            [v.rule for v in violations],
            [
                'DIALECT_NAME_BRANCH',
                'RAW_DIALECT_SQL',
                'RAW_DIALECT_SQL',
                'RAW_DIALECT_SQL',
                'DIALECT_SQL_FUNC',
                'DIALECT_SQL_FUNC',
                'DIALECT_SQL_FUNC',
                'RAW_ENGINE_BYPASS',
                'RAW_ENGINE_BYPASS',
            ],
        )

    def test_rejects_controller_sqlalchemy_persistence_and_any_non_persistence_write_admission(self):
        ctrl_src = dedent("""\
            import sqlalchemy as sa
            from sqlalchemy.exc import IntegrityError
            from .....persistence import mgr
            from .....persistence.write_admission import write_slot
        """)
        ctrl_violations = gate.scan_file('src/langbot/pkg/api/http/controller/groups/sample.py', ctrl_src)
        self.assertEqual(
            [(v.line, v.rule) for v in ctrl_violations],
            [
                (1, 'LAYER_IMPORT_VIOLATION'),
                (2, 'LAYER_IMPORT_VIOLATION'),
                (3, 'LAYER_IMPORT_VIOLATION'),
                (4, 'LAYER_IMPORT_VIOLATION'),
                (4, 'LAYER_IMPORT_VIOLATION'),
            ],
        )

        # Any non-persistence module (orchestrator, service, plugin, etc.) is blocked from write_admission.
        orch_src = 'from ...persistence.write_admission import sqlite_write_deadline\n'
        self.assertEqual(
            [v.rule for v in gate.scan_file('src/langbot/pkg/agent/runner/orchestrator.py', orch_src)],
            ['LAYER_IMPORT_VIOLATION'],
        )
        svc_src = 'from langbot.pkg.persistence.write_admission import write_slot\n'
        self.assertEqual(
            [v.rule for v in gate.scan_file('src/langbot/pkg/plugin/sample.py', svc_src)],
            ['LAYER_IMPORT_VIOLATION'],
        )

    def test_persistence_upward_import_blocked_for_all_upper_packages_except_type_checking_and_migrations(self):
        src = dedent("""\
            import typing
            from ..core import app as runtime_app
            from ..storage.media import MediaCache
            from ..cloud.bootstrap import SUPPORTED_PGVECTOR_DIMENSIONS

            if typing.TYPE_CHECKING:
                from ..core import app as typed_app
                from ..api.http import context as typed_ctx
        """)
        violations = gate.scan_file('src/langbot/pkg/persistence/sample.py', src)
        self.assertEqual(
            [(v.line, v.rule) for v in violations],
            [
                (2, 'LAYER_IMPORT_VIOLATION'),
                (3, 'LAYER_IMPORT_VIOLATION'),
                (4, 'LAYER_IMPORT_VIOLATION'),
            ],
        )

        # Frozen historical alembic migrations are exempted.
        mig_src = 'from langbot.pkg.command.processor import COMMAND_PROCESSOR_KIND\n'
        self.assertEqual(gate.scan_file('src/langbot/pkg/persistence/alembic/versions/0060_test.py', mig_src), [])

    def test_ratchet_blocks_new_violations_and_handles_tightening(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / 'src/langbot/pkg/box/legacy.py'
            target.parent.mkdir(parents=True)
            target.write_text('x = engine.dialect.name\n', encoding='utf-8')
            baseline = root / 'baseline.json'

            res = subprocess.run(
                [sys.executable, str(GATE), '--root', str(root), '--baseline', str(baseline), '--update-baseline'],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn('1 tracked legacy violations', res.stdout)

            for extra in ([], ['--strict-baseline']):
                ok = subprocess.run(
                    [sys.executable, str(GATE), '--root', str(root), '--baseline', str(baseline), *extra],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(ok.returncode, 0, (ok.stdout, ok.stderr))

            target.write_text('x = engine.dialect.name\ny = other.dialect.name\n', encoding='utf-8')
            bad = subprocess.run(
                [sys.executable, str(GATE), '--root', str(root), '--baseline', str(baseline)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(bad.returncode, 1)
            self.assertIn('DIALECT_NAME_BRANCH', bad.stdout)

            target.write_text('x = "clean"\n', encoding='utf-8')
            soft = subprocess.run(
                [sys.executable, str(GATE), '--root', str(root), '--baseline', str(baseline)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(soft.returncode, 0, (soft.stdout, soft.stderr))
            self.assertIn('baseline can be tightened', soft.stdout)

            strict = subprocess.run(
                [sys.executable, str(GATE), '--root', str(root), '--baseline', str(baseline), '--strict-baseline'],
                capture_output=True,
                text=True,
            )
            self.assertEqual(strict.returncode, 1)
            self.assertIn('strict baseline', strict.stdout)

    def test_import_from_counts_module_level_bans_once_and_preserves_per_alias_matches(self):
        # Single statement importing multiple symbols from write_admission counts once.
        ledger_src = 'from ...persistence.write_admission import commit_write, write_slot\n'
        ledger_violations = gate.scan_file('src/langbot/pkg/agent/runner/run_ledger_store.py', ledger_src)
        self.assertEqual([(v.line, v.rule) for v in ledger_violations], [(1, 'LAYER_IMPORT_VIOLATION')])

        # Controller importing multiple symbols from sqlalchemy counts once;
        # `from .....persistence import write_admission` still fires both controller and write_admission rules;
        # `from .....persistence.write_admission import commit_write, write_slot` fires each rule once (2 total, not 4).
        ctrl_src = dedent("""\
            from sqlalchemy import select, update, delete
            from .....persistence import write_admission
            from .....persistence.write_admission import commit_write, write_slot
        """)
        ctrl_violations = gate.scan_file('src/langbot/pkg/api/http/controller/groups/sample.py', ctrl_src)
        self.assertEqual(
            [(v.line, v.rule) for v in ctrl_violations],
            [
                (1, 'LAYER_IMPORT_VIOLATION'),
                (2, 'LAYER_IMPORT_VIOLATION'),
                (2, 'LAYER_IMPORT_VIOLATION'),
                (3, 'LAYER_IMPORT_VIOLATION'),
                (3, 'LAYER_IMPORT_VIOLATION'),
            ],
        )

        # Storage dialect import counts once for `from sqlalchemy.dialects.sqlite import a, b`
        # and once per dialect for `from sqlalchemy.dialects import postgresql, sqlite`.
        dialect_src = dedent("""\
            from sqlalchemy.dialects.sqlite import dialect, insert
            from sqlalchemy.dialects import postgresql, sqlite
        """)
        dialect_violations = gate.scan_file('src/langbot/pkg/pipeline/sample.py', dialect_src)
        self.assertEqual(
            [(v.line, v.rule) for v in dialect_violations],
            [
                (1, 'STORAGE_DIALECT_IMPORT'),
                (2, 'STORAGE_DIALECT_IMPORT'),
                (2, 'STORAGE_DIALECT_IMPORT'),
            ],
        )

        # Persistence upward import counts once for `from ..core import app, stage`
        # and once per package for `from .. import core, storage`.
        pers_src = dedent("""\
            from ..core import app, stage
            from .. import core, storage
        """)
        pers_violations = gate.scan_file('src/langbot/pkg/persistence/sample.py', pers_src)
        self.assertEqual(
            [(v.line, v.rule) for v in pers_violations],
            [
                (1, 'LAYER_IMPORT_VIOLATION'),
                (2, 'LAYER_IMPORT_VIOLATION'),
                (2, 'LAYER_IMPORT_VIOLATION'),
            ],
        )

    def test_load_baseline_rejects_bool_zero_and_empty_entries(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / 'src/langbot/pkg/box/clean.py'
            target.parent.mkdir(parents=True)
            target.write_text('x = 1\n', encoding='utf-8')

            empty_ok = root / 'empty_ok.json'
            empty_ok.write_text('{}\n', encoding='utf-8')
            self.assertEqual(gate.load_baseline(empty_ok), {})

            invalid_payloads = [
                {'src/langbot/pkg/box/clean.py': {'DIALECT_NAME_BRANCH': True}},
                {'src/langbot/pkg/box/clean.py': {'DIALECT_NAME_BRANCH': 0}},
                {'src/langbot/pkg/box/clean.py': {'DIALECT_NAME_BRANCH': -1}},
                {'src/langbot/pkg/box/clean.py': {}},
            ]
            for idx, payload in enumerate(invalid_payloads):
                bad_file = root / f'bad_{idx}.json'
                bad_file.write_text(json.dumps(payload), encoding='utf-8')
                with self.assertRaises(ValueError):
                    gate.load_baseline(bad_file)

                res = subprocess.run(
                    [
                        sys.executable,
                        str(GATE),
                        '--root',
                        str(root),
                        '--baseline',
                        str(bad_file),
                        '--strict-baseline',
                    ],
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(res.returncode, 0, (payload, res.stdout, res.stderr))
                self.assertIn('ERROR:', res.stderr)

    def test_default_root_independent_of_cwd_and_missing_src_root_fails(self):
        # Running from scripts/ without --root still scans the repository root accurately.
        from_scripts = subprocess.run(
            [sys.executable, str(GATE), '--strict-baseline'],
            cwd=str(SCRIPTS_DIR),
            capture_output=True,
            text=True,
        )
        self.assertEqual(from_scripts.returncode, 0, (from_scripts.stdout, from_scripts.stderr))

        # A root missing src/langbot must raise FileNotFoundError and exit non-zero via CLI.
        with TemporaryDirectory() as tmp:
            empty_root = Path(tmp)
            with self.assertRaises(FileNotFoundError):
                gate.scan_repo(empty_root)

            missing = subprocess.run(
                [sys.executable, str(GATE), '--root', str(empty_root)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(missing.returncode, 0, (missing.stdout, missing.stderr))
            self.assertIn('Source directory does not exist', missing.stderr)

    def test_repo_baseline_is_valid_and_synced_with_ruff_per_file_ignores(self):
        res = subprocess.run(
            [
                sys.executable,
                str(GATE),
                '--root',
                str(REPO_ROOT),
                '--baseline',
                str(BASELINE_FILE),
                '--strict-baseline',
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, (res.stdout, res.stderr))

        pyproject = tomllib.loads((REPO_ROOT / 'pyproject.toml').read_text(encoding='utf-8'))
        per_file = pyproject['tool']['ruff']['lint']['per-file-ignores']
        permanent = {
            'src/langbot/pkg/persistence/**',
            'src/langbot/pkg/vector/vdbs/pgvector_db.py',
            'tests/**',
            'tools/**',
            'scripts/**',
        }
        ruff_legacy = {path for path, codes in per_file.items() if 'TID251' in codes and path not in permanent}
        baseline = json.loads(BASELINE_FILE.read_text(encoding='utf-8'))
        ast_legacy = {path for path, rules in baseline.items() if 'STORAGE_DIALECT_IMPORT' in rules}
        self.assertEqual(ruff_legacy, ast_legacy)


if __name__ == '__main__':
    unittest.main(verbosity=2)
