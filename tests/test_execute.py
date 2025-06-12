import importlib
import sys

import pytest

import db

@pytest.fixture
def client(tmp_path, monkeypatch):
    original_path = db.DB_PATH
    db.DB_PATH = tmp_path / "test.db"
    db.init_db()

    if 'app' in sys.modules:
        importlib.reload(sys.modules['app'])
    else:
        importlib.import_module('app')
    app_module = sys.modules['app']
    app_module.app.config['TESTING'] = True

    with app_module.app.test_client() as client:
        with client.session_transaction() as sess:
            sess['username'] = 'SUPER'
        yield client

    db.DB_PATH = original_path
    db.init_db()
    if 'app' in sys.modules:
        importlib.reload(sys.modules['app'])


def _insert_command(name, extract_rule=None, endpoint=None):
    endpoint = endpoint or '/' + name.lower()
    conn = db.get_db_connection()
    conn.execute(
        'INSERT INTO commands (name, http_method, endpoint, extract_rule) VALUES (?, ?, ?, ?)',
        (name, 'GET', endpoint, extract_rule)
    )
    conn.commit()
    conn.close()


def test_execute_multiple_commands_single_line(client, monkeypatch):
    _insert_command('CmdA')
    _insert_command('CmdB')

    executed = []

    from app import http_session

    class Resp:
        status_code = 200
        text = '{}'

        def json(self):
            return {}

    def fake_request(method, url, headers=None, params=None, data=None):
        executed.append(url)
        return Resp()

    monkeypatch.setattr(http_session, 'request', fake_request)

    resp = client.post('/execute', data={'script': 'CmdA|CmdB'})
    assert resp.status_code == 200
    assert executed == ['/cmda', '/cmdb']


def test_lines_with_only_pipe_are_ignored(client, monkeypatch):
    _insert_command('Only')

    executed = []
    from app import http_session

    class Resp:
        status_code = 200
        text = '{}'

        def json(self):
            return {}

    monkeypatch.setattr(http_session, 'request', lambda *a, **kw: (executed.append(a[1]) or Resp()))

    script = '|\n|  \nOnly\n|'
    resp = client.post('/execute', data={'script': script})
    assert resp.status_code == 200
    assert executed == ['/only']
