import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_login_route(client):
    response = client.get('/login')
    assert response.status_code == 200


def test_successful_login_stores_password(client):
    resp = client.post('/login', data={'username': 'SUPER', 'password': 'SUPER'})
    assert resp.status_code == 302
    with client.session_transaction() as sess:
        assert sess.get('user_password') == 'SUPER'


def test_logout_removes_password(client):
    client.post('/login', data={'username': 'SUPER', 'password': 'SUPER'})
    resp = client.get('/logout')
    assert resp.status_code == 302
    with client.session_transaction() as sess:
        assert 'user_password' not in sess


def test_auth_cookie_endpoint(client):
    from app import http_session
    http_session.cookies.set('MOCA-WS-SESSIONKEY', 'cookie123')
    # Not logged in should give 401
    resp = client.get('/auth_cookie')
    assert resp.status_code == 401

    with client.session_transaction() as sess:
        sess['username'] = 'SUPER'

    resp2 = client.get('/auth_cookie')
    assert resp2.status_code == 200
    assert resp2.get_json()['cookie'] == 'cookie123'
    http_session.cookies.clear()

