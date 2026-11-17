import os
import pytest
from botocore.exceptions import ProfileNotFound, SSOTokenLoadError
from audithor.audithor_app import app
from audithor.collectors import utils
from tests.conftest import make_client

@pytest.fixture
def aws_files(tmp_path, monkeypatch):
    cred = tmp_path / 'credentials'
    cred.write_text('[default]\naws_access_key_id = KEY_DEFAULT\naws_secret_access_key = SECRET_DEFAULT\n[audit]\naws_access_key_id = KEY_AUDIT\naws_secret_access_key = SECRET_AUDIT\n')
    conf = tmp_path / 'config'
    conf.write_text('[profile sso-dev]\nsso_start_url = https://example.invalid/start\nsso_region = us-east-1\nsso_account_id = 123\nsso_role_name = ReadOnly\n[profile role-x]\nrole_arn = arn:aws:iam::123:role/x\nsource_profile = audit\n')
    monkeypatch.setenv('AWS_SHARED_CREDENTIALS_FILE', str(cred))
    monkeypatch.setenv('AWS_CONFIG_FILE', str(conf))
    monkeypatch.delenv('AWS_PROFILE', raising=False)
    monkeypatch.setenv('AUDITHOR_HOST', '127.0.0.1')
    return cred.read_text() + conf.read_text()

def test_list_profiles_names_only(aws_files):
    response = make_client(app).post('/api/aws-profiles', json={})
    assert response.status_code == 200
    body = response.get_json()
    assert body['profiles'] == ['audit', 'default', 'role-x', 'sso-dev']
    assert body['default'] == 'default'
    assert all(secret not in response.get_data(as_text=True) for secret in ['KEY_DEFAULT', 'SECRET_DEFAULT', 'KEY_AUDIT', 'SECRET_AUDIT'])

def test_profile_default_resolution(aws_files, monkeypatch):
    assert utils.list_aws_profiles()['default'] == 'default'
    monkeypatch.setenv('AWS_PROFILE', 'audit')
    assert utils.list_aws_profiles()['default'] == 'audit'

def test_nonloopback_blocks_profiles(aws_files, monkeypatch):
    monkeypatch.setenv('AUDITHOR_HOST', '0.0.0.0')
    client = make_client(app)
    assert client.post('/api/aws-profiles', json={}).get_json() == {'profiles': [], 'default': None, 'enabled': False}
    response = client.post('/api/run-acm-audit', json={'profile': 'audit'})
    assert response.status_code == 403

def test_unknown_profile_400(aws_files):
    response = make_client(app).post('/api/run-acm-audit', json={'profile':'missing'})
    assert response.status_code == 400

def test_missing_keys_collection_response(aws_files):
    response = make_client(app).post('/api/run-acm-audit', json={})
    assert response.status_code == 401
    assert 'scanId' in response.get_json()

def test_profile_session_sts(aws_files, monkeypatch):
    calls = []
    class STS:
        def get_caller_identity(self): return {'Account':'123'}
    class Session:
        available_profiles = ['audit']
        def __init__(self, **kwargs): calls.append(kwargs)
        def client(self, service, **kwargs): assert service == 'sts'; return STS()
    monkeypatch.setattr(utils.boto3, 'Session', Session)
    session, error = utils.get_session({'profile':'audit'})
    assert error is None and calls == [{}, {'profile_name':'audit'}]
    assert session._audithor_account_id == '123'

def test_sso_message_safe(aws_files, monkeypatch):
    class STS:
        def get_caller_identity(self): raise SSOTokenLoadError(error_msg='secret detail')
    class Session:
        available_profiles = ['sso-dev']
        def __init__(self, **kwargs): pass
        def client(self, *args, **kwargs): return STS()
    monkeypatch.setattr(utils.boto3, 'Session', Session)
    session, error = utils.get_session({'profile':'sso-dev'})
    assert session is None
    assert error == 'AWS SSO session expired or missing: run `aws sso login --profile sso-dev`'
    assert 'secret detail' not in error

def test_network_detail_uses_get_session(aws_files, monkeypatch):
    monkeypatch.setattr(utils, 'get_session', lambda *a, **k: (None, 'bad'))
    response = make_client(app).post('/api/run-network-detail-audit', json={'profile':'audit'})
    assert response.status_code != 500

def test_cloudwatch_no_session_per_region(monkeypatch):
    from audithor.collectors import cloudwatch
    calls = []
    class Client:
        def get_paginator(self, operation):
            class Paginator:
                def paginate(self, **kwargs): return []
            return Paginator()
    class Session:
        def client(self, service, **kwargs):
            calls.append((service, kwargs))
            return Client()
    monkeypatch.setattr(cloudwatch, 'get_all_aws_regions', lambda session: ['us-east-1'])
    monkeypatch.setattr(cloudwatch.boto3, 'Session', lambda *a, **k: pytest.fail('new session constructed'))
    assert cloudwatch.collect_cloudwatch_data(Session())['alarms'] == []
    assert calls == [(service, {'region_name': 'us-east-1'}) for service in ('cloudwatch', 'sns', 'logs')]

def test_sso_error_on_collection_route_is_safe(aws_files, monkeypatch):
    class STS:
        def get_caller_identity(self): raise SSOTokenLoadError(error_msg='secret detail')
    class Session:
        available_profiles = ['sso-dev']
        def __init__(self, **kwargs): pass
        def client(self, *args, **kwargs): return STS()
    monkeypatch.setattr(utils.boto3, 'Session', Session)
    response = make_client(app).post('/api/run-acm-audit', json={'profile':'sso-dev'})
    assert response.status_code == 401
    assert response.get_json()['error'] == 'AWS SSO session expired or missing: run `aws sso login --profile sso-dev`'
    assert 'secret detail' not in response.get_data(as_text=True)
