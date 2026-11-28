"""Optional resource lifecycle scenarios against the authenticated Workspace APIs."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import urllib.error
import urllib.request
from uuid import uuid4

from tools.regression.evidence import checked
from tools.regression.resource_cleanup import cleanup, journal
from tools.regression.regression_local_cases import ScenarioUnavailable, api, auth_headers, endpoint, require
from tools.entrypoints.regression_suite import resolve

GROUP = 'resources'
CASE_NAMES = {
    'auth_revocation',
    'agent_direct_execution',
    'retrieval_delete_visibility',
    'workspace_isolation',
    'artifact_storage_lifecycle',
    'runtime_connectivity_readiness',
}


def add_cases(profile):
    resources = {item['id']: item for item in profile['resources']}
    base = copy.deepcopy(resources['empty_knowledge_base'])
    base.update(id='resource_knowledge_base')
    base['body']['name'] = 'regression document lifecycle'
    base.pop('documents', None)
    profile['resources'].append(base)
    for name, stage, expected in (
        ('auth_revocation', 'auth', 'LANGBOT_AUTH_REVOCATION_OK'),
        ('agent_direct_execution', 'agent', 'LANGBOT_CHAT_OK'),
        ('retrieval_delete_visibility', 'retrieval', 'LANGBOT_DOCUMENT_DELETE_OK'),
        ('workspace_isolation', 'workspace', 'LANGBOT_WORKSPACE_ISOLATION_OK'),
        ('artifact_storage_lifecycle', 'storage', 'LANGBOT_ARTIFACT_STORAGE_OK'),
        ('runtime_connectivity_readiness', 'runtime', 'LANGBOT_RUNTIME_READY_OK'),
    ):
        profile['cases'].append({'name': name, 'scenario': name, 'stage': stage, 'expect': expected})


def raw_request(suite, method, path, *, headers=None, data=None):
    request_headers = dict(auth_headers(suite) if headers is None else headers)
    request = urllib.request.Request(
        endpoint(suite, path),
        method=method,
        headers=request_headers,
        data=data,
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        response = opener.open(request, timeout=suite.timeout(90))
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        response_headers = {key.lower(): value for key, value in response.headers.items()}
        return response.status, response_headers, response.read()


def upload_artifact(suite, filename, content, *, headers, mime_type='application/octet-stream', ttl_seconds=3600):
    boundary = 'qa' + uuid4().hex
    body = (
        (
            f'--{boundary}\r\n'
            f'Content-Disposition: form-data; name="ttl_seconds"\r\n\r\n'
            f'{ttl_seconds}\r\n'
            f'--{boundary}\r\n'
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f'Content-Type: {mime_type}\r\n\r\n'
        ).encode('utf-8')
        + content
        + f'\r\n--{boundary}--\r\n'.encode('utf-8')
    )
    request_headers = dict(headers)
    request_headers['Content-Type'] = 'multipart/form-data; boundary=' + boundary
    status, _, payload = raw_request(suite, 'POST', '/api/v1/artifacts', headers=request_headers, data=body)
    return status, json.loads(payload.decode('utf-8'))


def data(suite, method, path, body=None, *, headers=None):
    status, response = api(suite, method, path, body, headers=headers)
    require(
        status == 200 and isinstance(response, dict) and response.get('code') == 0,
        f'{method} {path} did not return a successful response (HTTP {status})',
    )
    return response.get('data', {})


def auth_revocation(suite, case, row):
    token = suite.env.get('LANGBOT_QA_USER_TOKEN')
    if not token:
        raise ScenarioUnavailable('auth.revocation requires LANGBOT_QA_USER_TOKEN with api_key.manage')
    if token not in suite.secrets:
        suite.secrets.append(token)
    manager = {'Authorization': 'Bearer ' + token}
    name = 'qa-revoke-' + uuid4().hex
    owned = {'kind': 'api-key', 'name': name, 'state': 'creating'}
    row.setdefault('owned_resources', []).append(owned)
    journal(suite, row)

    def revoke_owned():
        if 'id' not in owned:
            keys = data(suite, 'GET', '/api/v1/apikeys', headers=manager)['keys']
            matches = [key for key in keys if key.get('name') == name]
            require(len(matches) == 1, 'Created key identity is unresolved; inspect the resource journal')
            owned['id'] = matches[0]['id']
            journal(suite, row)
        path = f'/api/v1/apikeys/{owned["id"]}'
        key = data(suite, 'GET', path, headers=manager)['key']
        if key['status'] != 'revoked':
            data(suite, 'DELETE', path, headers=manager)
            key = data(suite, 'GET', path, headers=manager)['key']
        require(key['status'] == 'revoked', 'Owned credential remains active after cleanup')
        owned['state'] = 'revoked'

    try:
        created = data(suite, 'POST', '/api/v1/apikeys', {'name': name, 'scopes': ['resource.view']}, headers=manager)[
            'key'
        ]
        owned.update(id=created['id'], uuid=created['uuid'], state='active')
        journal(suite, row)
        secret = created['key']
        require(isinstance(secret, str) and bool(secret), 'Key creation did not return its one-time secret')
        suite.secrets.append(secret)
        child = {'X-API-Key': secret}
        identity = data(suite, 'GET', '/api/v1/system/context', headers=child)
        checked(
            row,
            'credential_active',
            lambda: require(
                identity.get('workspace_uuid') == suite.variables['workspace_uuid']
                and identity.get('api_key_id') == owned['uuid'],
                'New credential did not authenticate as its own Workspace key',
            ),
        )
        data(suite, 'GET', '/api/v1/pipelines', headers=child)
        data(suite, 'DELETE', f'/api/v1/apikeys/{owned["id"]}', headers=manager)
        status, response = api(suite, 'GET', '/api/v1/pipelines', headers=child)
        checked(
            row,
            'credential_revoked',
            lambda: require(
                status == 401 and isinstance(response, dict) and response.get('code') != 0,
                'Revoked credential still authorizes resource access',
            ),
        )
        key = data(suite, 'GET', f'/api/v1/apikeys/{owned["id"]}', headers=manager)['key']
        checked(
            row,
            'key_status',
            lambda: require(
                key.get('status') == 'revoked' and key.get('secret_available') is False and 'key' not in key,
                'Revoked key readback has incorrect status or exposes its secret',
            ),
        )
        return {'result': case['expect'], 'key_id': owned['id'], 'status': 'revoked'}
    finally:
        cleanup(suite, row, 'key_cleanup', revoke_owned)


def agent_direct_execution(suite, case, row):
    template = next(item for item in suite.profile['resources'] if item['id'] == 'chat_pipeline')
    config = resolve(copy.deepcopy(template['body']['config']['ai']), suite.variables)
    name = 'qa-agent-' + uuid4().hex
    conversation = 'qa-direct-' + uuid4().hex
    owned = {'kind': 'agent', 'name': name, 'state': 'creating'}
    row.setdefault('owned_resources', []).append(owned)
    journal(suite, row)

    def delete_owned():
        if 'uuid' not in owned:
            agents = data(suite, 'GET', '/api/v1/agents')['agents']
            matches = [agent for agent in agents if agent.get('name') == name and agent.get('kind') == 'agent']
            require(len(matches) == 1, 'Created Agent identity is unresolved; inspect the resource journal')
            owned['uuid'] = matches[0]['uuid']
            journal(suite, row)
        path = f'/api/v1/agents/{owned["uuid"]}'
        status, _ = api(suite, 'GET', path)
        if status != 404:
            require(status == 200, 'Cannot read owned Agent before cleanup')
            data(suite, 'DELETE', path)
        status, _ = api(suite, 'GET', path)
        require(status == 404, 'Owned Agent remains visible after cleanup')
        owned['state'] = 'deleted'

    try:
        created = data(suite, 'POST', '/api/v1/agents', {'name': name, 'kind': 'agent', 'config': config})
        owned.update(uuid=created['uuid'], state='created')
        journal(suite, row)
        path = f'/api/v1/agents/{owned["uuid"]}'
        reply = data(
            suite, 'POST', path + '/debug', {'text': 'Run the direct Agent scenario', 'conversation_id': conversation}
        )
        runs = data(suite, 'GET', path + '/runs')['items']
        matches = [run for run in runs if run.get('conversation_id') == conversation]
        require(len(matches) == 1, 'Direct Agent request did not produce exactly one matching Run')
        run = matches[0]
        row.setdefault('scenario_runs', []).append(
            {
                'run_id': run['run_id'],
                'conversation_id': conversation,
                'expected_status': 'completed',
                'after_id': row['after_id'],
            }
        )
        checked(
            row,
            'agent_terminal',
            lambda: require(
                run.get('status') == 'completed' and bool(run.get('finished_at')),
                'Direct Agent Run did not reach completed status',
            ),
        )
        checked(
            row,
            'agent_response',
            lambda: require(
                reply.get('conversation_id') == conversation and case['expect'] in reply.get('final_text', ''),
                'Direct Agent returned the wrong conversation or business reply',
            ),
        )
        events = data(suite, 'GET', path + f'/runs/{run["run_id"]}/events')
        checked(
            row,
            'agent_events',
            lambda: require(
                events.get('run', {}).get('run_id') == run['run_id']
                and any(
                    event.get('type') == 'run.completed' and event.get('run_id') == run['run_id']
                    for event in events.get('items', [])
                ),
                'Direct Agent completion event is missing',
            ),
        )
        return {'result': reply['final_text'], 'run_id': run['run_id'], 'conversation_id': conversation}
    finally:
        cleanup(suite, row, 'agent_cleanup', delete_owned)


def retrieval_delete_visibility(suite, case, row):
    kb_uuid = suite.variables['resource_knowledge_base']
    path = f'/api/v1/knowledge/bases/{kb_uuid}'
    before = {item['uuid'] for item in data(suite, 'GET', path + '/files')['files']}
    owned = {'kind': 'knowledge-files', 'knowledge_base_uuid': kb_uuid, 'files': [], 'state': 'ingesting'}
    row.setdefault('owned_resources', []).append(owned)
    journal(suite, row)

    def files():
        return [item for item in data(suite, 'GET', path + '/files')['files'] if item['uuid'] not in before]

    def cleanup_documents():
        remaining = files()
        owned['files'] = [{'uuid': item['uuid'], 'status': item['status']} for item in remaining]
        journal(suite, row)
        unresolved = [item['uuid'] for item in remaining if item['status'] in {'pending', 'processing', 'interrupted'}]
        for item in remaining:
            if item['uuid'] not in unresolved:
                data(suite, 'DELETE', path + '/files/' + item['uuid'])
        require(
            not unresolved, 'Document ingestion outcome is unresolved; retain the owned knowledge base for inspection'
        )
        require(not files(), 'Owned documents remain visible after cleanup')
        owned['state'] = 'deleted'

    def retrieve(query):
        found = data(suite, 'POST', path + '/retrieve', {'query': query, 'retrieval_settings': {'top_k': 10}})[
            'results'
        ]
        require(
            isinstance(found, list)
            and all(
                isinstance(item, dict)
                and isinstance(item.get('metadata'), dict)
                and isinstance(item.get('content'), list)
                for item in found
            ),
            'Malformed retrieval response',
        )
        return found

    def contains(found, document, marker):
        return any(
            item.get('metadata', {}).get('file_id') == document['engine_document_id']
            and marker in json.dumps(item.get('content', []), ensure_ascii=False)
            for item in found
        )

    try:
        documents, markers = [], ['obsolete' + uuid4().hex, 'retained' + uuid4().hex]
        with tempfile.TemporaryDirectory(prefix='resource-documents-', dir=suite.output) as directory:
            for index, marker in enumerate(markers):
                document = Path(directory) / f'document-{index}.txt'
                document.write_text(f'Lifecycle fixture: {marker}. This is document {index}.\n')
                previous = {item['uuid'] for item in files()}
                suite.call(
                    [
                        'knowledge-base',
                        'ingest',
                        kb_uuid,
                        '--file',
                        str(document),
                        '--parser-plugin-id',
                        'langbot-team/GeneralParsers',
                        '--wait',
                    ]
                )
                added = [item for item in files() if item['uuid'] not in previous]
                require(
                    len(added) == 1 and added[0].get('status') == 'completed',
                    'Document ingestion did not create exactly one completed file',
                )
                documents.append(added[0])
                owned['files'].append({'uuid': added[0]['uuid'], 'status': added[0]['status']})
                journal(suite, row)
        initial = retrieve(' '.join(markers))
        checked(
            row,
            'retrieval_initial',
            lambda: require(
                all(contains(initial, document, marker) for document, marker in zip(documents, markers)),
                'Both fixture documents must be independently retrievable before deletion',
            ),
        )
        data(suite, 'DELETE', path + '/files/' + documents[0]['uuid'])
        after = retrieve(' '.join(markers))
        checked(
            row,
            'retrieval_deleted',
            lambda: require(
                all(
                    item.get('metadata', {}).get('file_id') != documents[0]['engine_document_id']
                    and markers[0] not in json.dumps(item, ensure_ascii=False)
                    for item in after
                )
                and documents[0]['uuid'] not in {item['uuid'] for item in files()},
                'Deleted document remains visible in retrieval or the file list',
            ),
        )
        checked(
            row,
            'retrieval_control',
            lambda: require(
                contains(after, documents[1], markers[1]),
                'Deleting one document removed the surviving control document',
            ),
        )
        return {
            'result': case['expect'],
            'deleted_document_id': documents[0]['uuid'],
            'control_document_id': documents[1]['uuid'],
        }
    finally:
        cleanup(suite, row, 'document_cleanup', cleanup_documents)


def workspace_isolation(suite, case, row):
    token = suite.env.get('LANGBOT_QA_USER_TOKEN')
    if not token:
        raise ScenarioUnavailable('workspace_isolation requires LANGBOT_QA_USER_TOKEN')
    if token not in suite.secrets:
        suite.secrets.append(token)
    workspace_uuid = suite.variables['workspace_uuid']
    foreign_workspace = str(uuid4())
    while foreign_workspace == workspace_uuid:
        foreign_workspace = str(uuid4())
    manager = {'Authorization': 'Bearer ' + token, 'X-Workspace-Id': workspace_uuid}
    foreign_manager = {'Authorization': 'Bearer ' + token, 'X-Workspace-Id': foreign_workspace}
    marker = 'qa-ws-iso-' + uuid4().hex
    pipeline_name = marker + '-pipeline'
    pipeline_description = 'Workspace isolation fixture ' + marker
    key_name = marker + '-key'
    artifact_body = f'Workspace & principal isolated bytes: {marker}\n中文校验\n'.encode('utf-8')
    owned_pipeline = {'kind': 'pipeline', 'name': pipeline_name, 'state': 'creating'}
    owned_key = {'kind': 'api-key', 'name': key_name, 'state': 'creating'}
    owned_artifact = {'kind': 'artifact', 'name': marker + '.txt', 'state': 'creating'}
    row.setdefault('owned_resources', []).extend([owned_pipeline, owned_key, owned_artifact])
    journal(suite, row)

    def cleanup_all():
        errors = []
        try:
            if 'id' in owned_artifact:
                artifact_path = f'/api/v1/artifacts/{owned_artifact["id"]}'
                status, _ = api(suite, 'GET', artifact_path, headers=manager)
                if status != 404:
                    require(status == 200, 'Cannot read owned Artifact before cleanup')
                    api(suite, 'POST', artifact_path + '/release', headers=manager)
                    data(suite, 'DELETE', artifact_path, headers=manager)
                status, _ = api(suite, 'GET', artifact_path, headers=manager)
                require(status == 404, 'Owned Artifact remains visible after cleanup')
                owned_artifact['state'] = 'deleted'
        except Exception as exc:
            errors.append(f'artifact cleanup: {exc}')
        try:
            if 'uuid' not in owned_pipeline:
                pipelines = data(suite, 'GET', '/api/v1/pipelines', headers=manager)['pipelines']
                matches = [item for item in pipelines if item.get('name') == pipeline_name]
                if len(matches) == 1:
                    owned_pipeline['uuid'] = matches[0]['uuid']
                    journal(suite, row)
            if 'uuid' in owned_pipeline:
                pipeline_path = f'/api/v1/pipelines/{owned_pipeline["uuid"]}'
                status, _ = api(suite, 'GET', pipeline_path, headers=manager)
                if status != 404:
                    require(status == 200, 'Cannot read owned Pipeline before cleanup')
                    data(suite, 'DELETE', pipeline_path, headers=manager)
                status, _ = api(suite, 'GET', pipeline_path, headers=manager)
                require(status == 404, 'Owned Pipeline remains visible after cleanup')
                owned_pipeline['state'] = 'deleted'
        except Exception as exc:
            errors.append(f'pipeline cleanup: {exc}')
        try:
            if 'id' not in owned_key:
                keys = data(suite, 'GET', '/api/v1/apikeys', headers=manager)['keys']
                matches = [item for item in keys if item.get('name') == key_name]
                if len(matches) == 1:
                    owned_key['id'] = matches[0]['id']
                    journal(suite, row)
            if 'id' in owned_key:
                key_path = f'/api/v1/apikeys/{owned_key["id"]}'
                key = data(suite, 'GET', key_path, headers=manager)['key']
                if key.get('status') != 'revoked':
                    data(suite, 'DELETE', key_path, headers=manager)
                    key = data(suite, 'GET', key_path, headers=manager)['key']
                require(key.get('status') == 'revoked', 'Owned isolation API key remains active after cleanup')
                owned_key['state'] = 'revoked'
        except Exception as exc:
            errors.append(f'key cleanup: {exc}')
        require(not errors, '; '.join(errors))

    try:
        created_pipeline = data(
            suite,
            'POST',
            '/api/v1/pipelines',
            {'name': pipeline_name, 'description': pipeline_description},
            headers=manager,
        )
        owned_pipeline.update(uuid=created_pipeline['uuid'], state='created')
        journal(suite, row)
        pipeline_path = f'/api/v1/pipelines/{owned_pipeline["uuid"]}'

        created_key = data(
            suite,
            'POST',
            '/api/v1/apikeys',
            {'name': key_name, 'scopes': ['workspace.view', 'resource.view', 'resource.manage']},
            headers=manager,
        )['key']
        owned_key.update(id=created_key['id'], uuid=created_key['uuid'], state='active')
        journal(suite, row)
        child_secret = created_key['key']
        require(isinstance(child_secret, str) and bool(child_secret), 'Child API key did not return its secret')
        suite.secrets.append(child_secret)
        spoofed_key = {'X-API-Key': child_secret, 'X-Workspace-Id': foreign_workspace}
        child_key = {'X-API-Key': child_secret, 'X-Workspace-Id': workspace_uuid}

        upload_status, upload_payload = upload_artifact(
            suite,
            owned_artifact['name'],
            artifact_body,
            headers=manager,
            mime_type='text/plain',
            ttl_seconds=3600,
        )
        require(
            upload_status == 200 and isinstance(upload_payload, dict) and upload_payload.get('code') == 0,
            f'Owned Artifact upload failed (HTTP {upload_status})',
        )
        artifact_meta = upload_payload['data']
        owned_artifact.update(id=artifact_meta['id'], state='created')
        journal(suite, row)
        artifact_path = f'/api/v1/artifacts/{owned_artifact["id"]}'

        def check_read_denied():
            for path in (
                '/api/v1/pipelines',
                pipeline_path,
                '/api/v1/workspaces/current',
                f'/api/v1/workspaces/{foreign_workspace}',
            ):
                status, payload = api(suite, 'GET', path, headers=foreign_manager)
                encoded = json.dumps(payload, ensure_ascii=False)
                require(
                    status == 404
                    and isinstance(payload, dict)
                    and payload.get('code') != 0
                    and pipeline_name not in encoded
                    and owned_pipeline['uuid'] not in encoded,
                    f'Foreign Workspace selector was not rejected on GET {path} (HTTP {status})',
                )

        checked(row, 'workspace_read_denied', check_read_denied)

        def check_write_denied():
            for method, path, body in (
                ('PUT', pipeline_path, {'name': pipeline_name + '-mutated', 'description': 'cross-ws'}),
                ('DELETE', pipeline_path, None),
                ('POST', '/api/v1/pipelines', {'name': marker + '-foreign-create'}),
            ):
                status, payload = api(suite, method, path, body, headers=foreign_manager)
                require(
                    status == 404 and isinstance(payload, dict) and payload.get('code') != 0,
                    f'Foreign Workspace selector was not rejected on {method} {path} (HTTP {status})',
                )

        checked(row, 'workspace_write_denied', check_write_denied)

        def check_state_preserved():
            current = data(suite, 'GET', pipeline_path, headers=manager)['pipeline']
            require(
                current.get('uuid') == owned_pipeline['uuid']
                and current.get('name') == pipeline_name
                and current.get('description') == pipeline_description,
                'Rejected cross-Workspace writes mutated the owned Pipeline',
            )

        checked(row, 'workspace_state_preserved', check_state_preserved)

        original_lang = data(suite, 'GET', '/api/v1/workspaces/current/language', headers=manager)
        supported = original_lang.get('supported_languages') or ['en_US', 'zh_Hans']
        alternate_lang = next((item for item in supported if item != original_lang.get('language')), 'zh_Hans')

        def check_config_read_denied():
            status, payload = api(suite, 'GET', '/api/v1/workspaces/current/language', headers=foreign_manager)
            require(
                status == 404 and isinstance(payload, dict) and payload.get('code') != 0,
                f'Foreign Workspace selector read Workspace language config (HTTP {status})',
            )

        checked(row, 'workspace_config_read_denied', check_config_read_denied)

        def check_config_write_denied():
            status, payload = api(
                suite,
                'PUT',
                '/api/v1/workspaces/current/language',
                {'language': alternate_lang},
                headers=foreign_manager,
            )
            require(
                status == 404 and isinstance(payload, dict) and payload.get('code') != 0,
                f'Foreign Workspace selector mutated Workspace language config (HTTP {status})',
            )

        checked(row, 'workspace_config_write_denied', check_config_write_denied)

        def check_config_preserved():
            after_lang = data(suite, 'GET', '/api/v1/workspaces/current/language', headers=manager)
            require(
                after_lang.get('language') == original_lang.get('language'),
                'Workspace language config changed after rejected cross-Workspace write',
            )

        checked(row, 'workspace_config_preserved', check_config_preserved)

        def check_key_pinned():
            context = data(suite, 'GET', '/api/v1/system/context', headers=spoofed_key)
            require(
                context.get('workspace_uuid') == workspace_uuid and context.get('api_key_id') == owned_key['uuid'],
                'API key honored spoofed X-Workspace-Id header instead of staying pinned to its Workspace',
            )
            lang = data(suite, 'GET', '/api/v1/workspaces/current/language', headers=spoofed_key)
            require(
                lang.get('language') == original_lang.get('language'),
                'API key with spoofed X-Workspace-Id read unexpected Workspace config',
            )
            status, payload = api(
                suite,
                'PUT',
                '/api/v1/workspaces/current/language',
                {'language': alternate_lang},
                headers=spoofed_key,
            )
            require(
                status == 403 and isinstance(payload, dict) and payload.get('code') != 0,
                f'Workspace-view API key was allowed to mutate Workspace config (HTTP {status})',
            )

        checked(row, 'workspace_key_pinned', check_key_pinned)

        def check_artifact_read_denied():
            status, payload = api(suite, 'GET', artifact_path, headers=foreign_manager)
            require(
                status == 404 and isinstance(payload, dict) and payload.get('code') != 0,
                f'Foreign Workspace selector read Artifact metadata (HTTP {status})',
            )
            content_status, _, content_bytes = raw_request(
                suite, 'GET', artifact_path + '/content', headers=foreign_manager
            )
            require(
                content_status == 404 and artifact_body not in content_bytes,
                f'Foreign Workspace selector downloaded Artifact content (HTTP {content_status})',
            )

        checked(row, 'workspace_artifact_read_denied', check_artifact_read_denied)

        def check_artifact_write_denied():
            for method, path in (
                ('POST', artifact_path + '/retain'),
                ('DELETE', artifact_path),
            ):
                status, payload = api(suite, method, path, headers=foreign_manager)
                require(
                    status == 404 and isinstance(payload, dict) and payload.get('code') != 0,
                    f'Foreign Workspace selector was not rejected on {method} {path} (HTTP {status})',
                )

        checked(row, 'workspace_artifact_write_denied', check_artifact_write_denied)

        def check_principal_artifact_isolated():
            for headers in (child_key, spoofed_key):
                status, payload = api(suite, 'GET', artifact_path, headers=headers)
                require(
                    status == 404 and isinstance(payload, dict) and payload.get('code') != 0,
                    f'Another principal read Account-owned Artifact metadata (HTTP {status})',
                )
                content_status, _, content_bytes = raw_request(
                    suite, 'GET', artifact_path + '/content', headers=headers
                )
                require(
                    content_status == 404 and artifact_body not in content_bytes,
                    f'Another principal downloaded Account-owned Artifact bytes (HTTP {content_status})',
                )
                del_status, del_payload = api(suite, 'DELETE', artifact_path, headers=headers)
                require(
                    del_status == 404 and isinstance(del_payload, dict) and del_payload.get('code') != 0,
                    f'Another principal deleted Account-owned Artifact (HTTP {del_status})',
                )
            owner_status, _, owner_bytes = raw_request(suite, 'GET', artifact_path + '/content', headers=manager)
            require(
                owner_status == 200 and owner_bytes == artifact_body,
                'Owned Artifact bytes changed or disappeared after rejected probes',
            )

        checked(row, 'principal_artifact_isolated', check_principal_artifact_isolated)

        return {
            'result': case['expect'],
            'workspace_uuid': workspace_uuid,
            'pipeline_uuid': owned_pipeline['uuid'],
            'artifact_id': owned_artifact['id'],
        }
    finally:
        cleanup(suite, row, 'workspace_isolation_cleanup', cleanup_all)


def artifact_storage_lifecycle(suite, case, row):
    headers = auth_headers(suite)
    marker = 'qa-storage-' + uuid4().hex
    filename = marker + '.bin'
    payload_bytes = (f'Artifact storage contract: {marker}\n中文校验\n').encode('utf-8') + b'\x00\x01\x02\xff'
    expected_digest = hashlib.sha256(payload_bytes).hexdigest()
    owned = {'kind': 'artifact', 'name': filename, 'state': 'creating'}
    row.setdefault('owned_resources', []).append(owned)
    journal(suite, row)

    def cleanup_artifact():
        if 'id' not in owned:
            owned['state'] = 'absent'
            return
        artifact_path = f'/api/v1/artifacts/{owned["id"]}'
        status, _ = api(suite, 'GET', artifact_path, headers=headers)
        if status != 404:
            require(status == 200, 'Cannot read owned Artifact before cleanup')
            api(suite, 'POST', artifact_path + '/release', headers=headers)
            data(suite, 'DELETE', artifact_path, headers=headers)
        status, _ = api(suite, 'GET', artifact_path, headers=headers)
        require(status == 404, 'Owned Artifact remains visible after cleanup')
        owned['state'] = 'deleted'

    try:
        upload_status, upload_response = upload_artifact(
            suite,
            filename,
            payload_bytes,
            headers=headers,
            mime_type='application/octet-stream',
            ttl_seconds=3600,
        )

        def verify_upload():
            require(
                upload_status == 200 and isinstance(upload_response, dict) and upload_response.get('code') == 0,
                f'Artifact upload failed (HTTP {upload_status})',
            )
            meta = upload_response.get('data')
            require(
                isinstance(meta, dict)
                and isinstance(meta.get('id'), str)
                and meta['id'].startswith('art_')
                and meta.get('name') == filename
                and meta.get('size') == len(payload_bytes)
                and meta.get('digest') == expected_digest
                and meta.get('lifecycle') == 'temporary'
                and bool(meta.get('expires_at'))
                and 'content_ref' not in meta
                and 'locator' not in meta,
                'Uploaded Artifact metadata violates storage contract',
            )
            return meta

        uploaded = checked(row, 'artifact_upload', verify_upload)
        owned.update(id=uploaded['id'], state='created')
        journal(suite, row)
        artifact_path = f'/api/v1/artifacts/{uploaded["id"]}'

        def verify_metadata_readback():
            readback = data(suite, 'GET', artifact_path, headers=headers)
            require(readback == uploaded, 'Artifact metadata readback differs from upload receipt')
            return readback

        checked(row, 'artifact_metadata_readback', verify_metadata_readback)

        def verify_content_roundtrip():
            status, resp_headers, content = raw_request(suite, 'GET', artifact_path + '/content', headers=headers)
            require(
                status == 200
                and content == payload_bytes
                and resp_headers.get('etag') == f'"{expected_digest}"'
                and resp_headers.get('x-content-type-options') == 'nosniff'
                and 'no-store' in resp_headers.get('cache-control', ''),
                'Artifact download bytes or security headers violate storage contract',
            )

        checked(row, 'artifact_content_roundtrip', verify_content_roundtrip)

        def verify_max_bytes_guard():
            status, _, _ = raw_request(suite, 'GET', artifact_path + '/content?max_bytes=1', headers=headers)
            require(status == 413, f'Artifact max_bytes=1 did not return HTTP 413 (got {status})')

        checked(row, 'artifact_max_bytes_guard', verify_max_bytes_guard)

        def verify_unauthenticated_denied():
            status, _, _ = raw_request(suite, 'GET', artifact_path, headers={})
            require(status == 401, f'Unauthenticated Artifact metadata read did not return HTTP 401 (got {status})')

        checked(row, 'artifact_unauthenticated_denied', verify_unauthenticated_denied)

        def verify_retain():
            retained = data(suite, 'POST', artifact_path + '/retain', headers=headers)
            require(
                retained.get('id') == uploaded['id']
                and retained.get('lifecycle') == 'persistent'
                and retained.get('expires_at') is None,
                'Retaining Artifact did not transition lifecycle to persistent',
            )

        checked(row, 'artifact_retain_persistent', verify_retain)

        def verify_delete_blocked():
            status, response = api(suite, 'DELETE', artifact_path, headers=headers)
            require(
                status == 409 and isinstance(response, dict) and response.get('code') != 0,
                f'Deleting a retained Artifact did not return HTTP 409 (got {status})',
            )
            dl_status, _, content = raw_request(suite, 'GET', artifact_path + '/content', headers=headers)
            require(dl_status == 200 and content == payload_bytes, 'Retained Artifact became unreadable after 409')

        checked(row, 'artifact_delete_blocked_while_retained', verify_delete_blocked)

        def verify_release():
            released = data(suite, 'POST', artifact_path + '/release', headers=headers)
            require(
                released.get('id') == uploaded['id']
                and released.get('lifecycle') == 'temporary'
                and bool(released.get('expires_at')),
                'Releasing Artifact did not restore temporary lifecycle',
            )

        checked(row, 'artifact_release_temporary', verify_release)

        def verify_deleted_unavailable():
            deleted = data(suite, 'DELETE', artifact_path, headers=headers)
            require(
                deleted.get('id') == uploaded['id'] and deleted.get('deleted') is True,
                'Artifact deletion did not confirm deleted=true',
            )
            meta_status, _ = api(suite, 'GET', artifact_path, headers=headers)
            content_status, _, _ = raw_request(suite, 'GET', artifact_path + '/content', headers=headers)
            require(
                meta_status == 404 and content_status == 404,
                f'Deleted Artifact remained accessible (meta={meta_status}, content={content_status})',
            )
            owned['state'] = 'deleted'

        checked(row, 'artifact_deleted_unavailable', verify_deleted_unavailable)

        return {'result': case['expect'], 'artifact_id': uploaded['id'], 'digest': expected_digest}
    finally:
        cleanup(suite, row, 'artifact_cleanup', cleanup_artifact)


def runtime_connectivity_readiness(suite, case, row):
    token = suite.env.get('LANGBOT_QA_USER_TOKEN')
    if not token:
        raise ScenarioUnavailable('runtime_connectivity_readiness requires LANGBOT_QA_USER_TOKEN')
    if token not in suite.secrets:
        suite.secrets.append(token)
    manager = {'Authorization': 'Bearer ' + token, 'X-Workspace-Id': suite.variables['workspace_uuid']}

    def verify_plugin_ping():
        status = data(suite, 'GET', '/api/v1/system/status/plugin-system', headers=manager)
        require(
            status.get('is_enable') is True
            and status.get('is_connected') is True
            and status.get('plugin_connector_error') == 'ok',
            f'Plugin Runtime health ping failed: {status}',
        )
        return status

    plugin_status = checked(row, 'runtime_plugin_ping', verify_plugin_ping)

    def verify_box_ready():
        backend_status = data(suite, 'GET', '/api/v1/box/runtime-status', headers=manager)
        require(
            backend_status.get('enabled') is True
            and backend_status.get('available') is True
            and isinstance(backend_status.get('backend'), dict)
            and backend_status['backend'].get('available') is True,
            f'Box Runtime backend status is not ready: {backend_status}',
        )
        workspace_status = data(suite, 'GET', '/api/v1/box/status', headers=manager)
        require(
            workspace_status.get('enabled') is True and workspace_status.get('available') is True,
            f'Box Workspace status is not ready: {workspace_status}',
        )
        return {'backend': backend_status.get('backend', {}).get('name'), 'available': True}

    box_status = checked(row, 'runtime_box_ready', verify_box_ready)

    def verify_plugins_initialized():
        listed = data(suite, 'GET', '/api/v1/plugins', headers=manager).get('plugins', [])
        require(isinstance(listed, list), 'Plugin listing must be a list')
        initialized = {
            f'{item.get("manifest", {}).get("manifest", {}).get("metadata", {}).get("author") or item.get("author")}'
            f'/{item.get("manifest", {}).get("manifest", {}).get("metadata", {}).get("name") or item.get("name")}'
            for item in listed
            if item.get('enabled') is True and item.get('status') == 'initialized'
        }
        required = set(suite.profile.get('smoke', {}).get('required_plugins') or ('langbot-team/LocalAgent',))
        missing = sorted(required - initialized)
        require(not missing, f'Required Runtime plugins are not initialized: {missing}')
        return {'initialized': sorted(initialized)}

    plugins_ready = checked(row, 'runtime_plugins_initialized', verify_plugins_initialized)
    return {
        'result': case['expect'],
        'plugin_system': plugin_status,
        'box': box_status,
        'plugins': plugins_ready,
    }


def run_case(suite, case, row):
    actions = {
        'auth_revocation': auth_revocation,
        'agent_direct_execution': agent_direct_execution,
        'retrieval_delete_visibility': retrieval_delete_visibility,
        'workspace_isolation': workspace_isolation,
        'artifact_storage_lifecycle': artifact_storage_lifecycle,
        'runtime_connectivity_readiness': runtime_connectivity_readiness,
    }
    return actions[case['scenario']](suite, case, row)
