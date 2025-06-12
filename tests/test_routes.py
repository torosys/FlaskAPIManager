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

