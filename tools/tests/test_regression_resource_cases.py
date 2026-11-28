"""Challenge public resource lifecycle oracles and their cleanup without starting services."""

import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.regression.regression_local_cases import ScenarioUnavailable
from tools.regression.regression_resource_cases import run_case


def success(data=None):
    return 200, {'code': 0, 'data': data or {}}


class ResourceCasesTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.suite = SimpleNamespace(
            output=self.root,
            env={'LANGBOT_QA_USER_TOKEN': 'private-user-token'},
            secrets=[],
            variables={'workspace_uuid': 'workspace', 'resource_knowledge_base': 'owned-kb'},
            profile={
                'resources': [
                    {
                        'id': 'chat_pipeline',
                        'body': {'config': {'ai': {'runner': {'id': 'runner'}, 'runner_config': {'runner': {}}}}},
                    }
                ]
            },
            write=lambda name, value: (self.root / name).write_text(json.dumps(value)),
        )

    def test_missing_management_session_skips_without_creating_credentials(self):
        self.suite.env.clear()
        with patch('tools.regression.regression_resource_cases.api') as request, self.assertRaises(ScenarioUnavailable):
            run_case(self.suite, {'scenario': 'auth_revocation'}, {})
        request.assert_not_called()

    def test_revocation_rejects_still_authorized_key_and_never_persists_secrets(self):
        for stale_authorization in (False, True):
            with self.subTest(stale_authorization=stale_authorization):
                key = {'id': 7, 'uuid': 'managed-key', 'status': 'active', 'secret_available': False}
                row = {'after_id': 0}

                def request(suite, method, path, body=None, headers=None):
                    if method == 'POST':
                        return success({'key': {**key, 'key': 'private-child-secret', 'secret_available': True}})
                    if method == 'DELETE':
                        key['status'] = 'revoked'
                        return success()
                    if path == '/api/v1/system/context':
                        self.assertEqual(headers, {'X-API-Key': 'private-child-secret'})
                        return success({'workspace_uuid': 'workspace', 'api_key_id': 'managed-key'})
                    if path == '/api/v1/pipelines':
                        return (
                            success({'pipelines': []})
                            if key['status'] == 'active' or stale_authorization
                            else (401, {'code': -1})
                        )
                    return success({'key': key})

                with patch('tools.regression.regression_resource_cases.api', side_effect=request):
                    case = {'scenario': 'auth_revocation', 'expect': 'REVOKED'}
                    if stale_authorization:
                        with self.assertRaisesRegex(ValueError, 'still authorizes'):
                            run_case(self.suite, case, row)
                        self.assertEqual(row['assertions']['credential_revoked'], 'failed')
                    else:
                        self.assertEqual(run_case(self.suite, case, row)['status'], 'revoked')
                self.assertEqual(key['status'], 'revoked')
                self.assertEqual(row['assertions']['key_cleanup'], 'passed')
                evidence = json.dumps(row) + (self.root / row['resource_journal']).read_text()
                self.assertNotIn('private-child-secret', evidence)
                self.assertNotIn('private-user-token', evidence)

    def test_direct_agent_records_run_and_cleans_after_failed_public_event_oracle(self):
        for missing_event in (False, True):
            with self.subTest(missing_event=missing_event):
                state, row = {}, {'after_id': 12}

                def request(suite, method, path, body=None, headers=None):
                    if method == 'POST' and path == '/api/v1/agents':
                        state.update(uuid='own-agent', name=body['name'])
                        return success({'uuid': 'own-agent'})
                    if path.endswith('/debug'):
                        state['conversation'] = body['conversation_id']
                        return success({'conversation_id': state['conversation'], 'final_text': 'DIRECT_OK'})
                    run = {
                        'run_id': 'own-run',
                        'conversation_id': state.get('conversation'),
                        'status': 'completed',
                        'finished_at': 1,
                    }
                    if path.endswith('/runs'):
                        return success({'items': [run]})
                    if path.endswith('/events'):
                        return success(
                            {
                                'run': run,
                                'items': [] if missing_event else [{'type': 'run.completed', 'run_id': 'own-run'}],
                            }
                        )
                    if method == 'DELETE':
                        self.assertEqual(path, '/api/v1/agents/own-agent')
                        state['deleted'] = True
                        return success()
                    return (404, {'code': -1}) if state.get('deleted') else success({'agent': state})

                with patch('tools.regression.regression_resource_cases.api', side_effect=request):
                    case = {'scenario': 'agent_direct_execution', 'expect': 'DIRECT_OK'}
                    if missing_event:
                        with self.assertRaisesRegex(ValueError, 'completion event'):
                            run_case(self.suite, case, row)
                    else:
                        self.assertEqual(run_case(self.suite, case, row)['run_id'], 'own-run')
                self.assertEqual(
                    row['scenario_runs'],
                    [
                        {
                            'run_id': 'own-run',
                            'conversation_id': state['conversation'],
                            'after_id': 12,
                            'expected_status': 'completed',
                        }
                    ],
                )
                self.assertTrue(state['deleted'])
                self.assertEqual(row['assertions']['agent_cleanup'], 'passed')

    def test_unknown_agent_create_recovers_owned_identity_without_retrying_creation(self):
        calls, state, row = [], {}, {'after_id': 0}

        def request(suite, method, path, body=None, headers=None):
            calls.append((method, path))
            if method == 'POST':
                state.update(uuid='own-agent', name=body['name'], kind='agent')
                raise ConnectionResetError('creation response lost')
            if path == '/api/v1/agents':
                return success({'agents': [state, {'uuid': 'unrelated', 'name': 'other', 'kind': 'agent'}]})
            if method == 'DELETE':
                self.assertEqual(path, '/api/v1/agents/own-agent')
                state['deleted'] = True
                return success()
            return (404, {'code': -1}) if state.get('deleted') else success({'agent': state})

        with (
            patch('tools.regression.regression_resource_cases.api', side_effect=request),
            self.assertRaises(ConnectionResetError),
        ):
            run_case(self.suite, {'scenario': 'agent_direct_execution', 'expect': 'OK'}, row)
        self.assertEqual(sum(method == 'POST' for method, _ in calls), 1)
        self.assertEqual(row['owned_resources'][0]['state'], 'deleted')

    def test_delete_requires_retrieval_absence_and_preserves_control_document(self):
        for stale_vectors in (False, True):
            with self.subTest(stale_vectors=stale_vectors):
                documents, row = [], {'after_id': 0}

                def ingest(args):
                    content = Path(args[args.index('--file') + 1]).read_text()
                    index = len(documents)
                    documents.append(
                        {
                            'uuid': f'file-{index}',
                            'engine_document_id': f'engine-{index}',
                            'status': 'completed',
                            'content': content,
                            'deleted': False,
                        }
                    )
                    return {}

                def request(suite, method, path, body=None, headers=None):
                    if method == 'DELETE':
                        target = next(document for document in documents if path.endswith('/' + document['uuid']))
                        target['deleted'] = True
                        return success()
                    if method == 'GET':
                        return success({'files': [document for document in documents if not document['deleted']]})
                    return success(
                        {
                            'results': [
                                {
                                    'metadata': {'file_id': document['engine_document_id']},
                                    'content': [{'type': 'text', 'text': document['content']}],
                                }
                                for document in documents
                                if not document['deleted'] or stale_vectors
                            ]
                        }
                    )

                self.suite.call = ingest
                with patch('tools.regression.regression_resource_cases.api', side_effect=request):
                    case = {'scenario': 'retrieval_delete_visibility', 'expect': 'DELETED'}
                    if stale_vectors:
                        with self.assertRaisesRegex(ValueError, 'remains visible'):
                            run_case(self.suite, case, row)
                        self.assertEqual(row['assertions']['retrieval_deleted'], 'failed')
                    else:
                        self.assertEqual(run_case(self.suite, case, row)['result'], 'DELETED')
                        self.assertEqual(row['assertions']['retrieval_control'], 'passed')
                self.assertTrue(all(document['deleted'] for document in documents))
                self.assertEqual(row['assertions']['document_cleanup'], 'passed')
                self.assertEqual(list(self.root.glob('resource-documents-*')), [])

    def test_workspace_isolation_enforces_selector_config_key_pinning_and_artifact_boundaries(self):
        self.suite.env.clear()
        with (
            patch('tools.regression.regression_resource_cases.api') as mock_api,
            self.assertRaises(ScenarioUnavailable),
        ):
            run_case(self.suite, {'scenario': 'workspace_isolation', 'expect': 'OK'}, {})
        mock_api.assert_not_called()

        for fault in (None, 'foreign_pipeline_read', 'principal_artifact_read'):
            with self.subTest(fault=fault):
                self.suite.env = {'LANGBOT_QA_USER_TOKEN': 'private-user-token'}
                self.suite.secrets = []
                state = {
                    'pipeline': None,
                    'key': {'id': 9, 'uuid': 'child-key-uuid', 'status': 'active', 'secret_available': False},
                    'artifact': None,
                    'language': 'en_US',
                }
                row = {'after_id': 0}

                def fake_api(suite, method, path, body=None, headers=None):
                    headers = headers or {}
                    ws_header = headers.get('X-Workspace-Id')
                    is_api_key = 'X-API-Key' in headers
                    is_foreign = not is_api_key and ws_header and ws_header != 'workspace'

                    if is_foreign:
                        if fault == 'foreign_pipeline_read' and method == 'GET' and path == '/api/v1/pipelines':
                            return success({'pipelines': [state['pipeline']]})
                        return 404, {'code': 'resource_not_found'}

                    if path == '/api/v1/pipelines' and method == 'POST':
                        state['pipeline'] = {
                            'uuid': 'own-pipe',
                            'name': body['name'],
                            'description': body['description'],
                        }
                        return success({'uuid': 'own-pipe'})
                    if path == '/api/v1/pipelines' and method == 'GET':
                        return success({'pipelines': [state['pipeline']] if state['pipeline'] else []})
                    if path == '/api/v1/pipelines/own-pipe':
                        if method == 'DELETE':
                            state['pipeline'] = None
                            return success()
                        return (
                            (404, {'code': -1})
                            if state['pipeline'] is None
                            else success({'pipeline': state['pipeline']})
                        )
                    if path == '/api/v1/apikeys' and method == 'POST':
                        state['key']['name'] = body['name']
                        return success(
                            {'key': {**state['key'], 'key': 'private-iso-child-key', 'secret_available': True}}
                        )
                    if path == '/api/v1/apikeys/9':
                        if method == 'DELETE':
                            state['key']['status'] = 'revoked'
                            return success()
                        return success({'key': state['key']})
                    if path == '/api/v1/system/context':
                        self.assertEqual(headers.get('X-API-Key'), 'private-iso-child-key')
                        return success({'workspace_uuid': 'workspace', 'api_key_id': 'child-key-uuid'})
                    if path == '/api/v1/workspaces/current/language':
                        if method == 'GET':
                            return success({'language': state['language'], 'supported_languages': ['en_US', 'zh_Hans']})
                        if is_api_key:
                            return 403, {'code': 'permission_denied'}
                        state['language'] = body['language']
                        return success({'language': state['language']})
                    if path.startswith('/api/v1/artifacts/'):
                        if is_api_key:
                            if fault == 'principal_artifact_read' and method == 'GET':
                                return success(state['artifact']['meta'])
                            return 404, {'code': 'resource_not_found'}
                        if path.endswith('/release'):
                            return success(state['artifact']['meta'])
                        if method == 'DELETE':
                            state['artifact'] = None
                            return success({'id': 'art_' + 'a' * 32, 'deleted': True})
                        if state['artifact'] is None:
                            return 404, {'code': 'resource_not_found'}
                        return success(state['artifact']['meta'])
                    raise AssertionError(f'Unexpected api call: {method} {path}')

                def fake_upload(
                    suite, filename, content, *, headers, mime_type='application/octet-stream', ttl_seconds=3600
                ):
                    meta = {
                        'id': 'art_' + 'a' * 32,
                        'name': filename,
                        'size': len(content),
                        'digest': hashlib.sha256(content).hexdigest(),
                        'lifecycle': 'temporary',
                        'expires_at': '2026-11-29T00:00:00+00:00',
                    }
                    state['artifact'] = {'meta': meta, 'content': content}
                    return success(meta)

                def fake_raw(suite, method, path, *, headers=None, data=None):
                    headers = headers or {}
                    ws_header = headers.get('X-Workspace-Id')
                    is_api_key = 'X-API-Key' in headers
                    if not is_api_key and ws_header and ws_header != 'workspace':
                        return 404, {}, b'{"code":"resource_not_found"}'
                    if is_api_key:
                        return 404, {}, b'{"code":"resource_not_found"}'
                    return 200, {}, state['artifact']['content']

                with (
                    patch('tools.regression.regression_resource_cases.api', side_effect=fake_api),
                    patch('tools.regression.regression_resource_cases.upload_artifact', side_effect=fake_upload),
                    patch('tools.regression.regression_resource_cases.raw_request', side_effect=fake_raw),
                ):
                    case = {'scenario': 'workspace_isolation', 'expect': 'LANGBOT_WORKSPACE_ISOLATION_OK'}
                    if fault == 'foreign_pipeline_read':
                        with self.assertRaisesRegex(ValueError, 'Foreign Workspace selector'):
                            run_case(self.suite, case, row)
                        self.assertEqual(row['assertions']['workspace_read_denied'], 'failed')
                    elif fault == 'principal_artifact_read':
                        with self.assertRaisesRegex(ValueError, 'Another principal read'):
                            run_case(self.suite, case, row)
                        self.assertEqual(row['assertions']['principal_artifact_isolated'], 'failed')
                    else:
                        result = run_case(self.suite, case, row)
                        self.assertEqual(result['result'], 'LANGBOT_WORKSPACE_ISOLATION_OK')
                        for check_name in (
                            'workspace_read_denied',
                            'workspace_write_denied',
                            'workspace_state_preserved',
                            'workspace_config_read_denied',
                            'workspace_config_write_denied',
                            'workspace_config_preserved',
                            'workspace_key_pinned',
                            'workspace_artifact_read_denied',
                            'workspace_artifact_write_denied',
                            'principal_artifact_isolated',
                        ):
                            self.assertEqual(row['assertions'][check_name], 'passed')
                self.assertIsNone(state['pipeline'])
                self.assertIsNone(state['artifact'])
                self.assertEqual(state['key']['status'], 'revoked')
                self.assertEqual(row['assertions']['workspace_isolation_cleanup'], 'passed')
                evidence = json.dumps(row) + (self.root / row['resource_journal']).read_text()
                self.assertNotIn('private-iso-child-key', evidence)
                self.assertNotIn('private-user-token', evidence)

    def test_artifact_storage_lifecycle_roundtrip_retain_release_delete_and_cleanup(self):
        for allow_retained_delete in (False, True):
            with self.subTest(allow_retained_delete=allow_retained_delete):
                state = {'meta': None, 'content': None, 'retained': False}
                row = {'after_id': 0}

                def fake_upload(
                    suite, filename, content, *, headers, mime_type='application/octet-stream', ttl_seconds=3600
                ):
                    state['content'] = content
                    state['meta'] = {
                        'id': 'art_' + 'b' * 32,
                        'name': filename,
                        'mime_type': mime_type,
                        'size': len(content),
                        'digest': hashlib.sha256(content).hexdigest(),
                        'lifecycle': 'temporary',
                        'expires_at': '2026-11-29T00:00:00+00:00',
                    }
                    return success(dict(state['meta']))

                def fake_api(suite, method, path, body=None, headers=None):
                    if state['meta'] is None:
                        return 404, {'code': 'resource_not_found'}
                    if path.endswith('/retain') and method == 'POST':
                        state['retained'] = True
                        state['meta']['lifecycle'] = 'persistent'
                        state['meta']['expires_at'] = None
                        return success(dict(state['meta']))
                    if path.endswith('/release') and method == 'POST':
                        state['retained'] = False
                        state['meta']['lifecycle'] = 'temporary'
                        state['meta']['expires_at'] = '2026-11-29T00:00:00+00:00'
                        return success(dict(state['meta']))
                    if method == 'DELETE':
                        if state['retained'] and not allow_retained_delete:
                            return 409, {'code': 'artifact_in_use'}
                        aid = state['meta']['id']
                        state['meta'] = None
                        state['content'] = None
                        return success({'id': aid, 'deleted': True})
                    return success(dict(state['meta']))

                def fake_raw(suite, method, path, *, headers=None, data=None):
                    if not headers:
                        return 401, {}, b'{"code":"invalid_authentication"}'
                    if state['meta'] is None:
                        return 404, {}, b'{"code":"resource_not_found"}'
                    if 'max_bytes=1' in path:
                        return 413, {}, b'{"code":"artifact_too_large"}'
                    return (
                        200,
                        {
                            'etag': f'"{state["meta"]["digest"]}"',
                            'x-content-type-options': 'nosniff',
                            'cache-control': 'private, no-store',
                        },
                        state['content'],
                    )

                with (
                    patch(
                        'tools.regression.regression_resource_cases.auth_headers',
                        return_value={'Authorization': 'Bearer k'},
                    ),
                    patch('tools.regression.regression_resource_cases.upload_artifact', side_effect=fake_upload),
                    patch('tools.regression.regression_resource_cases.api', side_effect=fake_api),
                    patch('tools.regression.regression_resource_cases.raw_request', side_effect=fake_raw),
                ):
                    case = {'scenario': 'artifact_storage_lifecycle', 'expect': 'LANGBOT_ARTIFACT_STORAGE_OK'}
                    if allow_retained_delete:
                        with self.assertRaisesRegex(ValueError, 'HTTP 409'):
                            run_case(self.suite, case, row)
                        self.assertEqual(row['assertions']['artifact_delete_blocked_while_retained'], 'failed')
                    else:
                        res = run_case(self.suite, case, row)
                        self.assertEqual(res['result'], 'LANGBOT_ARTIFACT_STORAGE_OK')
                        for check_name in (
                            'artifact_upload',
                            'artifact_metadata_readback',
                            'artifact_content_roundtrip',
                            'artifact_max_bytes_guard',
                            'artifact_unauthenticated_denied',
                            'artifact_retain_persistent',
                            'artifact_delete_blocked_while_retained',
                            'artifact_release_temporary',
                            'artifact_deleted_unavailable',
                        ):
                            self.assertEqual(row['assertions'][check_name], 'passed')
                self.assertIsNone(state['meta'])
                self.assertEqual(row['assertions']['artifact_cleanup'], 'passed')

    def test_runtime_connectivity_readiness_checks_ping_box_and_plugins(self):
        self.suite.env.clear()
        with self.assertRaises(ScenarioUnavailable):
            run_case(self.suite, {'scenario': 'runtime_connectivity_readiness', 'expect': 'OK'}, {})

        for fault in (None, 'disconnected_runtime', 'missing_plugin'):
            with self.subTest(fault=fault):
                self.suite.env = {'LANGBOT_QA_USER_TOKEN': 'private-user-token'}
                self.suite.profile['smoke'] = {'required_plugins': ['langbot-team/LocalAgent']}
                row = {}

                def fake_api(suite, method, path, body=None, headers=None):
                    if path == '/api/v1/system/status/plugin-system':
                        connected = fault != 'disconnected_runtime'
                        return success(
                            {
                                'is_enable': True,
                                'is_connected': connected,
                                'plugin_connector_error': 'ok' if connected else 'ws closed',
                            }
                        )
                    if path == '/api/v1/box/runtime-status':
                        return success(
                            {'enabled': True, 'available': True, 'backend': {'name': 'docker', 'available': True}}
                        )
                    if path == '/api/v1/box/status':
                        return success({'enabled': True, 'available': True})
                    if path == '/api/v1/plugins':
                        plugins = (
                            []
                            if fault == 'missing_plugin'
                            else [
                                {
                                    'enabled': True,
                                    'status': 'initialized',
                                    'manifest': {
                                        'manifest': {'metadata': {'author': 'langbot-team', 'name': 'LocalAgent'}}
                                    },
                                }
                            ]
                        )
                        return success({'plugins': plugins})
                    raise AssertionError(f'Unexpected api call: {method} {path}')

                with patch('tools.regression.regression_resource_cases.api', side_effect=fake_api):
                    case = {'scenario': 'runtime_connectivity_readiness', 'expect': 'LANGBOT_RUNTIME_READY_OK'}
                    if fault == 'disconnected_runtime':
                        with self.assertRaisesRegex(ValueError, 'Plugin Runtime health ping'):
                            run_case(self.suite, case, row)
                        self.assertEqual(row['assertions']['runtime_plugin_ping'], 'failed')
                    elif fault == 'missing_plugin':
                        with self.assertRaisesRegex(ValueError, 'not initialized'):
                            run_case(self.suite, case, row)
                        self.assertEqual(row['assertions']['runtime_plugins_initialized'], 'failed')
                    else:
                        res = run_case(self.suite, case, row)
                        self.assertEqual(res['result'], 'LANGBOT_RUNTIME_READY_OK')
                        self.assertEqual(row['assertions']['runtime_plugin_ping'], 'passed')
                        self.assertEqual(row['assertions']['runtime_box_ready'], 'passed')
                        self.assertEqual(row['assertions']['runtime_plugins_initialized'], 'passed')


if __name__ == '__main__':
    unittest.main()
