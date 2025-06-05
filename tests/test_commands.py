import os
import importlib
import sys

import pytest

import db


@pytest.fixture
def client(tmp_path):
    # Backup original DB_PATH and switch to temporary database
    original_path = db.DB_PATH
    db.DB_PATH = tmp_path / "test.db"
    db.init_db()

    # Reload app so it picks up the temporary DB
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

    # Cleanup: restore original DB_PATH and reinitialize default DB
    db.DB_PATH = original_path
    db.init_db()
    if 'app' in sys.modules:
        importlib.reload(sys.modules['app'])


def test_get_command_form(client):
    resp = client.get('/commands/form')
    assert resp.status_code == 200
    assert b'<form' in resp.data


def test_post_command_and_persist(client):
    data = {
        'name': 'Sample',
        'http_method': 'GET',
        'endpoint': '/sample'
    }
    resp = client.post('/commands', data=data)
    assert resp.status_code == 200

    conn = db.get_db_connection()
    row = conn.execute('SELECT * FROM commands WHERE name=?', ('Sample',)).fetchone()
    conn.close()
    assert row is not None

