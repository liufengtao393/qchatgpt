"""Coverage must measure evaluated obligations, not green request counters."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.regression.evidence import checked

from tools.entrypoints.regression_coverage import (
    check_required_priorities,
    collect,
    http_observations,
    load_catalog,
    report,
    route_inventory,
    write_report,
)


def catalog():
    return {
        'version': 1,
        'scope': 'Test scope',
        'contracts': [
            {
                'id': 'reply',
                'area': 'conversation',
                'kind': 'blackbox',
                'priority': 'P0',
                'description': 'Reply and payload agree',
                'bindings': [{'profile': 'smoke', 'case': 'chat', 'checks': ['response', 'fields']}],
            },
            {
                'id': 'terminal',
                'area': 'execution',
                'kind': 'graybox',
                'priority': 'P0',
                'description': 'Persisted terminal state',
                'bindings': [{'profile': 'smoke', 'case': 'chat', 'checks': ['ledger']}],
            },
            {
                'id': 'recovery',
                'area': 'execution',
                'kind': 'blackbox',
                'priority': 'P0',
                'description': 'Restart recovery',
                'bindings': [],
            },
        ],
    }


def row(**overrides):
    return {'profile': 'smoke', 'case': 'chat', 'status': 'passed', **overrides}


class CoverageTest(unittest.TestCase):
    def test_old_green_rows_and_transport_failures_are_not_coverage(self):
        for r in [row(), row(status='unknown'), row(assertions={'response': 'passed'})]:
            data = report(catalog(), [r])
            self.assertEqual(data['kinds']['blackbox']['decided'], 0)
            self.assertEqual(data['contracts'][0]['status'], 'incomplete')
        r = {}
        with self.assertRaises(TimeoutError):
            checked(r, 'response', lambda: (_ for _ in ()).throw(TimeoutError('transport')))
        self.assertNotIn('response', r['assertions'])

    def test_a_failed_assertion_is_covered_but_not_passed(self):
        r = row()
        with self.assertRaises(ValueError):
            checked(r, 'response', lambda: (_ for _ in ()).throw(ValueError('wrong reply')))
        data = report(catalog(), [r])
        self.assertEqual(data['kinds']['blackbox']['coverage_percent'], 50)
        self.assertEqual(data['kinds']['blackbox']['pass_percent'], 0)
        self.assertEqual(data['contracts'][0]['status'], 'failed')

    def test_graybox_failure_does_not_erase_external_assertions(self):
        data = report(
            catalog(),
            [
                row(
                    status='failed',
                    assertions={
                        'response': 'passed',
                        'fields': 'passed',
                        'ledger': 'failed',
                    },
                )
            ],
        )
        self.assertEqual(data['contracts'][0]['status'], 'passed')
        self.assertEqual(data['contracts'][1]['status'], 'failed')
        self.assertEqual(data['contracts'][2]['status'], 'missing_test')

    def test_repetition_does_not_inflate_coverage_or_hide_incomplete_turns(self):
        good = row(assertions={'response': 'passed', 'fields': 'passed'})
        self.assertEqual(report(catalog(), [good])['kinds'], report(catalog(), [good] * 100)['kinds'])
        mixed = report(catalog(), [good, row(status='unknown')])
        self.assertEqual(mixed['contracts'][0]['status'], 'incomplete')
        self.assertEqual(report(catalog(), [row(status='skipped')])['contracts'][0]['status'], 'skipped')
        self.assertEqual(report(catalog(), [])['contracts'][0]['status'], 'not_run')

    def test_first_turn_does_not_prove_history_and_unclassified_cases_are_visible(self):
        c = catalog()
        c['contracts'][0]['bindings'][0]['min_turn'] = 2
        r = row(turn=1, assertions={'response': 'passed', 'fields': 'passed'})
        data = report(c, [r, row(case='new_case')])
        self.assertEqual(data['contracts'][0]['status'], 'not_run')
        self.assertEqual(data['unclassified_cases'], [{'profile': 'smoke', 'case': 'new_case'}])

    def test_reset_failure_and_peer_skip_cannot_be_hidden_by_first_turns(self):
        c = load_catalog()
        rows = [
            {
                'profile': 'scenarios',
                'case': 'group_reset_isolation',
                'status': 'passed',
                'group_index': group,
                'turn': 1,
                'assertions': {'response': 'passed'},
            }
            for group in (0, 1)
        ]
        rows += [
            {
                'profile': 'scenarios',
                'case': 'group_reset_isolation',
                'status': 'failed',
                'group_index': 0,
                'turn': 2,
                'assertions': {'reset': 'failed'},
            },
            {'profile': 'scenarios', 'case': 'group_reset_isolation', 'status': 'skipped', 'group_index': 1, 'turn': 2},
        ]
        selected = [
            x for x in report(c, rows)['contracts'] if any(b['case'] == 'group_reset_isolation' for b in x['bindings'])
        ]
        self.assertEqual(sorted(x['status'] for x in selected), ['failed', 'skipped'])

    def test_partial_evidence_produces_an_error_and_a_report(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'profile.json').write_text(json.dumps({'coverage_suite': 'smoke', 'smoke': {}}))
            (root / 'cases.json').write_text('[{"case":')
            rows, errors = collect(root)
            self.assertEqual(rows, [])
            self.assertEqual(len(errors), 1)
            result = write_report([root], root)
            self.assertTrue(result['evidence_errors'])
            self.assertEqual(result['kinds']['blackbox']['decided'], 0)
            self.assertTrue((root / 'coverage.md').is_file())

    def test_api_requires_every_planned_round_and_its_named_assertions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            current_catalog = catalog()
            current_catalog['contracts'] = [current_catalog['contracts'][0]]
            bindings = current_catalog['contracts'][0]['bindings']
            bindings[0].update(profile='api', case='fixed_api_chat')
            bindings.append(dict(bindings[0], case='shuffled_api_chat'))
            catalog_path = root / 'catalog.json'
            catalog_path.write_text(json.dumps(current_catalog))
            profile = {
                'coverage_suite': 'api',
                'smoke': {},
                'vars': {'api_fixed_only': False},
                'cases': [{'name': b['case']} for b in bindings],
            }
            (root / 'profile.json').write_text(json.dumps(profile))
            fixed = {
                'case': 'fixed_api_chat',
                'status': 'passed',
                'contract_ids': ['reply'],
                'assertions': {'response': 'passed', 'fields': 'passed'},
            }
            shuffled = dict(fixed, case='shuffled_api_chat')
            for executed, complete in (
                ([fixed], False),
                ([fixed, fixed], False),
                ([fixed, dict(shuffled, assertions={'response': 'passed'})], False),
                ([fixed, dict(shuffled, contract_ids=['wrong-id'])], False),
                ([fixed, shuffled], True),
            ):
                with self.subTest(executed=executed):
                    (root / 'cases.json').write_text(json.dumps(executed))
                    observed, errors = collect(root, catalog_path)
                    data = report(current_catalog, observed, errors)
                    self.assertEqual(data['complete_evidence'], complete)
                    self.assertEqual(data['contracts'][0]['status'], 'passed' if complete else 'incomplete')

            (root / 'cases.json').write_text(json.dumps([fixed]))
            profile['cases'].pop()
            (root / 'profile.json').write_text(json.dumps(profile))
            observed, errors = collect(root, catalog_path)
            self.assertIn('required cases', errors[0])
            self.assertEqual(report(current_catalog, observed, errors)['contracts'][0]['status'], 'incomplete')

            profile['vars']['api_fixed_only'] = True
            (root / 'profile.json').write_text(json.dumps(profile))
            observed, errors = collect(root, catalog_path)
            self.assertFalse(errors)
            self.assertEqual(report(current_catalog, observed, errors)['contracts'][0]['status'], 'passed')

    def test_missing_phase_evidence_cannot_hide_behind_a_successful_phase(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'profile.json').write_text(
                json.dumps(
                    {
                        'coverage_suite': 'smoke',
                        'phases': [{'name': 'first'}, {'name': 'second'}],
                    }
                )
            )
            (root / 'first').mkdir()
            (root / 'first/requests.jsonl').write_text(
                json.dumps(
                    row(
                        assertions={'response': 'passed', 'fields': 'passed'},
                    )
                )
                + '\n'
            )
            rows, errors = collect(root)
            self.assertEqual(len(rows), 1)
            self.assertEqual(len(errors), 1)
            self.assertFalse(report(catalog(), rows, errors)['complete_evidence'])

    def test_empty_and_absent_planned_cases_are_explicit_evidence_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'profile.json').write_text(
                json.dumps(
                    {
                        'coverage_suite': 'smoke',
                        'smoke': {},
                        'cases': [{'name': 'chat'}],
                    }
                )
            )
            (root / 'cases.json').write_text('[]')
            rows, errors = collect(root)
            self.assertEqual(rows, [])
            self.assertTrue(any('empty' in error for error in errors))
            self.assertTrue(any('planned cases' in error for error in errors))

    def test_http_hits_use_method_templates_and_do_not_retain_private_urls(self):
        inventory = {
            'routes': [
                {'route': value}
                for value in (
                    'GET /things/<uuid>',
                    'GET /things/new',
                    'POST /things/<uuid>',
                    'POST /bots/<id>/<path:path>',
                )
            ]
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'access.log'
            path.write_text(
                '\n'.join(
                    [
                        'GET /things/new?token=secret 1.1 200',
                        'GET /things/private-id 1.1 404',
                        'POST /things/private-id 1.1 403',
                        'POST /bots/private-bot/reset 1.1 200',
                        'GET /unknown/private-id 1.1 404',
                        'application log is not a request',
                    ]
                )
            )
            result = http_observations([path], inventory)
            self.assertEqual(result['records'], 5)
            self.assertEqual(len(result['routes']), 4)
            self.assertEqual(result['unclassified'], {'GET 404': 1})
            encoded = json.dumps(result)
            for value in ('private-id', 'private-bot', 'secret'):
                self.assertNotIn(value, encoded)
            self.assertTrue(http_observations([path.with_name('missing')], inventory)['evidence_errors'])

    def test_http_converter_and_invalid_url_do_not_create_false_hits_or_leaks(self):
        inventory = {'routes': [{'route': 'GET /keys/<int:id>'}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'access.log'
            path.write_text(
                '\n'.join(
                    [
                        'GET /keys/not-an-int 1.1 404',
                        'GET http://[private-tenant]/?token=secret 1.1 400',
                        'GET /keys/42 1.1 200',
                    ]
                )
            )
            result = http_observations([path], inventory)
            self.assertEqual(result['routes'], [{'route': 'GET /keys/<int:id>', 'statuses': {'200': 1}}])
            self.assertEqual(result['unclassified'], {'GET 404': 1, 'GET 400': 1})
            self.assertEqual(len(result['evidence_errors']), 1)
            self.assertNotIn('private-tenant', json.dumps(result))
            self.assertNotIn('secret', json.dumps(result))

    def test_suite_finalization_rejects_missing_evidence_for_direct_callers(self):
        from tools.entrypoints.regression_suite import Suite

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = {
                'version': 1,
                'coverage_suite': 'smoke',
                'smoke': {},
                'cli': {'config': 'unused'},
                'cases': [{'name': 'chat'}],
            }
            suite = Suite(profile, root / 'input.json', root)
            suite.write('profile.json', profile)
            result = {'errors': []}
            suite.finish(result)
            self.assertFalse(result['passed'])
            self.assertTrue((root / 'coverage.json').exists())
            self.assertFalse(json.loads((root / 'summary.json').read_text())['passed'])

    def test_new_routes_are_discovered_without_adding_test_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'src/langbot/pkg/example.py'
            source.parent.mkdir(parents=True)
            source.write_text("""
@group.group_class('example', '/api/example')
class Routes:
    async def initialize(self):
        @self.route('/new', methods=['POST'])
        async def new_operation(): pass
        @self.route(dynamic_path)
        async def dynamic_operation(): pass
""")
            inventory = route_inventory(catalog(), root)
            self.assertEqual(inventory['routes'][0]['route'], 'POST /api/example/new')
            self.assertEqual(inventory['routes'][0]['contracts'], [])
            self.assertEqual(len(inventory['unresolved']), 1)

    def test_catalog_bindings_name_real_cases_and_required_checks(self):
        c = load_catalog()
        profiles = {}
        routes = {r['route'] for r in route_inventory(c)['routes']}
        for contract in c['contracts']:
            self.assertTrue(set(contract.get('routes', [])) <= routes)
            for binding in contract['bindings']:
                name = binding['profile']
                if name not in profiles:
                    path = Path(__file__).resolve().parents[1] / 'profiles' / f'{name}.json'
                    if name in ('api', 'state', 'isolation', 'plugin-lifecycle', 'cli'):
                        from tools.entrypoints.regression_ci import suite_profile

                        profile, _ = suite_profile(name, 'catalog-test')
                    elif name == 'scenarios':
                        from tools.regression.regression_scenarios import expanded_profile
                        from tools.regression.regression_local_cases import DEFAULT_GROUPS

                        profile = expanded_profile(DEFAULT_GROUPS)
                        if 'lifecycle' in DEFAULT_GROUPS:
                            from tools.regression.regression_lifecycle_cases import restart_profile

                            profile['cases'] += restart_profile(profile)['cases']
                    else:
                        profile = json.loads(path.read_text())
                    profiles[name] = {x['name']: x for x in profile['cases']}
                self.assertIn(binding['case'], profiles[name])
                self.assertTrue(binding['checks'])
        broken = copy.deepcopy(c)
        broken['contracts'].append(broken['contracts'][0])
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'catalog.json'
            path.write_text(json.dumps(broken))
            with self.assertRaises(ValueError):
                load_catalog(path)

    def test_catalog_validation_rejects_hollow_checks_and_covers_high_risk_p0_areas(self):
        c = load_catalog()
        for invalid_checks in ([], [''], ['  '], ['response', 'response']):
            broken = copy.deepcopy(c)
            broken['contracts'][0]['bindings'][0]['checks'] = invalid_checks
            with tempfile.TemporaryDirectory() as d:
                path = Path(d) / 'catalog.json'
                path.write_text(json.dumps(broken))
                with self.assertRaises(ValueError):
                    load_catalog(path)

        p0_blackbox = [item for item in c['contracts'] if item['kind'] == 'blackbox' and item['priority'] == 'P0']
        self.assertTrue(p0_blackbox)
        self.assertEqual([item['id'] for item in p0_blackbox if not item['bindings']], [])
        for area in ('persistence', 'storage', 'agent', 'runtime', 'workspace', 'isolation'):
            area_p0 = [item for item in p0_blackbox if item['area'] == area]
            self.assertGreaterEqual(len(area_p0), 4, f'Expected >=4 bound P0 blackbox contracts in {area}')

        empty_report = report(c, [])
        self.assertEqual(empty_report['priorities']['P0']['passed'], 0)
        self.assertEqual(empty_report['priorities']['P0']['status']['not_run'], len(p0_blackbox))
        self.assertEqual(empty_report['priorities']['P0']['status']['missing_test'], 0)
        gate = check_required_priorities(empty_report, ('P0',))
        self.assertFalse(gate['passed'])
        self.assertEqual(len(gate['unmet']), len(p0_blackbox))

    def test_priority_and_area_dashboard_reports_achievement_and_status_breakdown(self):
        c = {
            'version': 1,
            'scope': 'Dashboard scope',
            'contracts': [
                {
                    'id': 'storage.ok',
                    'area': 'storage',
                    'kind': 'blackbox',
                    'priority': 'P0',
                    'description': 'Passed storage contract',
                    'bindings': [{'profile': 'scenarios', 'case': 's1', 'checks': ['a']}],
                },
                {
                    'id': 'storage.fail',
                    'area': 'storage',
                    'kind': 'blackbox',
                    'priority': 'P0',
                    'description': 'Failed storage contract',
                    'bindings': [{'profile': 'scenarios', 'case': 's2', 'checks': ['b']}],
                },
                {
                    'id': 'runtime.not_run',
                    'area': 'runtime',
                    'kind': 'blackbox',
                    'priority': 'P0',
                    'description': 'Not run runtime contract',
                    'bindings': [{'profile': 'scenarios', 'case': 's3', 'checks': ['c']}],
                },
                {
                    'id': 'agent.incomplete',
                    'area': 'agent',
                    'kind': 'blackbox',
                    'priority': 'P1',
                    'description': 'Incomplete agent contract',
                    'bindings': [{'profile': 'scenarios', 'case': 's4', 'checks': ['d1', 'd2']}],
                },
                {
                    'id': 'persistence.gap',
                    'area': 'persistence',
                    'kind': 'blackbox',
                    'priority': 'P2',
                    'description': 'Unbound gap',
                    'bindings': [],
                },
                {
                    'id': 'isolation.gray',
                    'area': 'isolation',
                    'kind': 'graybox',
                    'priority': 'P0',
                    'description': 'Graybox must not inflate blackbox priority counts',
                    'bindings': [{'profile': 'scenarios', 'case': 's1', 'checks': ['a']}],
                },
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalog_path = root / 'catalog.json'
            catalog_path.write_text(json.dumps(c))
            run_dir = root / 'run'
            run_dir.mkdir()
            (run_dir / 'profile.json').write_text(json.dumps({'coverage_suite': 'scenarios', 'smoke': {}}))
            (run_dir / 'cases.json').write_text(
                json.dumps(
                    [
                        {'case': 's1', 'status': 'passed', 'assertions': {'a': 'passed'}},
                        {'case': 's2', 'status': 'failed', 'assertions': {'b': 'failed'}},
                        {'case': 's4', 'status': 'passed', 'assertions': {'d1': 'passed'}},
                    ]
                )
            )
            out_dir = root / 'out'
            data = write_report([run_dir], out_dir, catalog_path=catalog_path, require_priorities=('P0',))
            self.assertEqual(data['priorities']['P0']['total'], 3)
            self.assertEqual(data['priorities']['P0']['passed'], 1)
            self.assertEqual(data['priorities']['P0']['achievement_percent'], 33.33)
            self.assertEqual(data['priorities']['P0']['status']['failed'], 1)
            self.assertEqual(data['priorities']['P0']['status']['not_run'], 1)
            self.assertEqual(data['priorities']['P1']['status']['incomplete'], 1)
            self.assertEqual(data['priorities']['P2']['status']['missing_test'], 1)
            self.assertEqual(data['areas']['storage']['passed'], 1)
            self.assertEqual(data['areas']['storage']['total'], 2)
            self.assertEqual(data['areas']['storage']['achievement_percent'], 50.0)
            self.assertEqual(data['areas']['runtime']['status']['not_run'], 1)
            self.assertNotIn('isolation', data['areas'])
            self.assertFalse(data['priority_gate']['passed'])
            self.assertEqual(
                [item['id'] for item in data['priority_gate']['unmet']], ['runtime.not_run', 'storage.fail']
            )
            markdown = (out_dir / 'coverage.md').read_text()
            self.assertIn('## Blackbox progress by priority', markdown)
            self.assertIn('| P0 | 1/3 | 33.33% | 1 | 0 | 0 | 1 | 0 |', markdown)
            self.assertIn('## Blackbox progress by area', markdown)
            self.assertIn('| storage | 1/2 | 50.0% | 1 | 0 | 0 | 0 | 0 |', markdown)
            self.assertIn('## Priority gate', markdown)
            self.assertIn('Required blackbox priorities: P0 — FAIL (1/3).', markdown)

    def test_require_priority_cli_blocks_missing_or_incomplete_p0_and_passes_when_complete(self):
        c = {
            'version': 1,
            'scope': 'CLI gate scope',
            'contracts': [
                {
                    'id': 'p0.one',
                    'area': 'workspace',
                    'kind': 'blackbox',
                    'priority': 'P0',
                    'description': 'First P0 contract',
                    'bindings': [{'profile': 'smoke', 'case': 'c1', 'checks': ['ok']}],
                },
                {
                    'id': 'p0.two',
                    'area': 'storage',
                    'kind': 'blackbox',
                    'priority': 'P0',
                    'description': 'Second P0 contract',
                    'bindings': [{'profile': 'smoke', 'case': 'c2', 'checks': ['ok']}],
                },
                {
                    'id': 'p1.optional',
                    'area': 'agent',
                    'kind': 'blackbox',
                    'priority': 'P1',
                    'description': 'Unrun P1 contract does not block P0 gate',
                    'bindings': [{'profile': 'scenarios', 'case': 'c3', 'checks': ['ok']}],
                },
            ],
        }
        repo_root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            catalog_path = root / 'catalog.json'
            catalog_path.write_text(json.dumps(c))
            run_dir = root / 'run'
            run_dir.mkdir()
            (run_dir / 'profile.json').write_text(json.dumps({'coverage_suite': 'smoke', 'smoke': {}}))

            # Missing c2 -> P0 gate must fail with exit code 1.
            (run_dir / 'cases.json').write_text(
                json.dumps([{'case': 'c1', 'status': 'passed', 'assertions': {'ok': 'passed'}}])
            )
            fail_out = root / 'out-fail'
            proc = subprocess.run(
                [
                    sys.executable,
                    '-m',
                    'tools.entrypoints.regression_coverage',
                    '--run',
                    str(run_dir),
                    '--output',
                    str(fail_out),
                    '--catalog',
                    str(catalog_path),
                    '--require-priority',
                    'P0',
                ],
                cwd=repo_root,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn('p0.two', proc.stderr)
            self.assertFalse(json.loads((fail_out / 'coverage.json').read_text())['priority_gate']['passed'])

            # Both P0 passed (even though P1 is not_run) -> P0 gate passes with exit code 0.
            (run_dir / 'cases.json').write_text(
                json.dumps(
                    [
                        {'case': 'c1', 'status': 'passed', 'assertions': {'ok': 'passed'}},
                        {'case': 'c2', 'status': 'passed', 'assertions': {'ok': 'passed'}},
                    ]
                )
            )
            pass_out = root / 'out-pass'
            proc = subprocess.run(
                [
                    sys.executable,
                    '-m',
                    'tools.entrypoints.regression_coverage',
                    '--run',
                    str(run_dir),
                    '--output',
                    str(pass_out),
                    '--catalog',
                    str(catalog_path),
                    '--require-priority',
                    'P0',
                ],
                cwd=repo_root,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            saved = json.loads((pass_out / 'coverage.json').read_text())
            self.assertTrue(saved['priority_gate']['passed'])
            self.assertEqual(saved['priority_gate']['passed_count'], 2)
            self.assertIn('Required blackbox priorities: P0 — PASS (2/2).', (pass_out / 'coverage.md').read_text())

            # Evidence errors must block priority gate even if contracts look passed.
            bad_report = report(
                c,
                [
                    {'profile': 'smoke', 'case': 'c1', 'status': 'passed', 'assertions': {'ok': 'passed'}},
                    {'profile': 'smoke', 'case': 'c2', 'status': 'passed', 'assertions': {'ok': 'passed'}},
                ],
                errors=['corrupt log'],
            )
            self.assertFalse(check_required_priorities(bad_report, ('P0',))['passed'])


if __name__ == '__main__':
    unittest.main()
