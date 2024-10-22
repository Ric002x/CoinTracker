import pytest

from .extension import db
from .models import User
from .run import create_app


@pytest.fixture
def app():
    app = create_app(test=True)
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:'
    })
    db.init_app(app)

    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def runner(app):
    return app.test_cli_runner


def create_user(
    email='test@email.com',
    password='TestPassword1',
    username="Username"
):
    user = User(
        email=email,
        password=None,
        google_id=None,
        username=username
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


def test_home_page(client):
    response = client.get('/')
    assert response.status_code == 200
    assert "Acompanhe a variação de fluxo cambial do dólar" in response.text


def test_login_page(client):
    response = client.get('/login')
    assert response.status_code == 200
    assert b"Login" in response.data


def test_login_post_failed(client):
    response = client.post('/login', data={
        'email': 'test@example.com',
        'password': 'wrongpassword'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Login" in response.data


# def test_login_successful(client):
#     user = create_user()

#     response = client.post('/login', data={
#         "email": user.email,
#         "password": "TestPassword1"
#     }, follow_redirects=True)
#     assert 'Verifique o Valor do Dólar' in response.text
