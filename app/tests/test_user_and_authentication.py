from ..extension import db
from ..models import User


def create_user(
    email='test@email.com',
    password='Password1',
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


def generate_user_data(
        email="test@email.com",
        username="Username",
        password="Password1",
        repeat_password="Password1"):
    user_data = {
        "email": email,
        "username": username,
        "password": password,
        'repeat_password': repeat_password
    }
    return user_data


def generate_password_form(
    old_password="Password1",
    new_password="NewPass1",
    repeat_password="NewPass1"
):
    password_data = {
        "old_password": old_password,
        "new_password": new_password,
        "repeat_password": repeat_password,
    }
    return password_data


def login_user(client):
    user = create_user()
    client.post('/login', data={
        "email": user.email,
        "password": "Password1"
    }, follow_redirects=True)


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
    assert "E-mail ou senha inválidos" in response.text


def test_login_form_fields_are_required(client):
    user_data = {"email": "test@email.com", "password": "Password1"}
    for key, value in user_data.items():
        user_data[key] = ""
        response = client.post('/login', data=user_data)
        assert "Campo obrigatório" in response.text


def test_login_successful(client):
    user = create_user()

    response = client.post('/login', data={
        "email": user.email,
        "password": "Password1"
    }, follow_redirects=True)
    assert 'Verifique o Valor do Dólar' in response.text


def test_register_page(client):
    response = client.get('/register')
    assert response.status_code == 200
    assert b"Registrar-se" in response.data


def test_register_post_failed_and_form_errors(client):
    user_data = generate_user_data(
        email="username", username="user",
        password="invalidpassword", repeat_password="diferent_password"
    )
    response = client.post(
        '/register', data=user_data, follow_redirects=True)
    assert "Formato de email inválido" in response.text
    assert "As senha não coincidem" in response.text
    assert "O nome de usuário precisa ter pelo menos " \
        "5 caracteres" in response.text


def test_register_password_validation_regex(client):
    user_data = generate_user_data(
        password="invalidpassword", repeat_password="invalidpassword"
    )
    response = client.post(
        '/register', data=user_data, follow_redirects=True)
    assert "A senha deve contar pelo menos 8 caracteres, incluindo " \
        "letras maiúsculas e números" in response.text


def test_register_user_email_is_unique(client):
    create_user()
    user_data = generate_user_data(username="User2")
    response = client.post(
        '/register', data=user_data, follow_redirects=True)
    assert "Já existe um usuário cadastrado com esse email" in response.text


def test_register_form_fields_can_not_be_empty(client):
    user_data = generate_user_data()
    for key, value in user_data.items():
        user_data[key] = ""
        response = client.post(
            '/register', data=user_data, follow_redirects=True)
        assert "Campo obrigatório" in response.text


def test_register_successfull(client):
    user_data = generate_user_data()
    response = client.post(
        '/register', data=user_data, follow_redirects=True)
    assert "Usuário cadastrado! Faça login para continuar" in response.text
    assert b"Logar" in response.data


def test_update_user_infos_page(client):
    login_user(client)
    response = client.get('/user/update')
    assert response.status_code == 200
    assert "Atualizar Dados" in response.text


def test_update_page_load_user_info(client):
    login_user(client)
    response = client.get('/user/update')
    assert "test@email.com" in response.text
    assert "wrongemail@email.com" not in response.text


def test_update_user_infos_failed(client):
    login_user(client)
    response = client.post('/user/update', data={
        "username": "user",
        "email": "test@"
    }, follow_redirects=True)
    assert "O nome de usuário precisa ter pelo menos" in response.text
    assert "Formato de email inválido" in response.text


def test_update_user_email_cant_be_equal_to_anther_user_email(client):
    not_logged_user = create_user(
        email="teste2@email.com", username="User2"
    )
    login_user(client)
    response = client.post('/user/update', data={
        "email": not_logged_user.email
    }, follow_redirects=True)
    assert "Já existe um usuário cadastrado com esse email" in response.text


def test_update_user_successful(client):
    login_user(client)
    response = client.post('/user/update', data={
        "username": "new_username",
        "email": "new_email@email.com"
    }, follow_redirects=True)
    assert "new_username" in response.text
    assert "new_email@email.com" in response.text

    response2 = client.post('/user/update', data={
        "username": "new_username2",
    }, follow_redirects=True)
    assert "new_username2" in response2.text
    assert "new_email@email.com" in response2.text


def test_change_password_page(client):
    login_user(client)
    response = client.get('/user/change-password')
    assert "Alterar senha" in response.text
    assert response.status_code == 200


def test_change_password_form_errors(client):
    login_user(client)
    password_data = generate_password_form(old_password="WrongPassword")
    response1 = client.post('/user/change-password',
                            data=password_data, follow_redirects=True)
    assert "A senha inserida não coincide com a senha salva" in response1.text
    assert "Erro no formulário" in response1.text

    password_data = generate_password_form(repeat_password="WrongPassword")
    response2 = client.post('/user/change-password',
                            data=password_data, follow_redirects=True)
    assert "As senha não coincidem" in response2.text
    assert "Erro no formulário" in response2.text

    password_data = generate_password_form(
        new_password="invalidpasswordregex",
        repeat_password="invalidpasswordregex")
    response3 = client.post('/user/change-password',
                            data=password_data, follow_redirects=True)
    assert "A senha deve contar pelo menos 8 caracteres, incluindo " \
        "letras maiúsculas e números" in response3.text


def test_change_password_succesfully(client):
    login_user(client)
    password_data = generate_password_form()
    response = client.post('/user/change-password',
                           data=password_data, follow_redirects=True)
    assert "Senha atualizada com sucesso" in response.text

    # Login with new password:
    client.get('/logout')

    # See if user if of the session
    login_page = client.get('/login')
    assert b"Login" in login_page.data

    new_login = client.post('/login', data={
        "email": "test@email.com",
        "password": "Password1"
    }, follow_redirects=True)
    assert "E-mail ou senha inválidos" in new_login.text


def test_logout_redirect_if_not_user_in_session(client):
    response = client.get('/logout')
    assert response.status_code == 302
    assert "/" in response.location


def test_logout_succesful(client):
    login_user(client)
    response = client.get('/logout', follow_redirects=True)
    assert response.status_code == 200
    assert "Logout feito com sucesso" in response.text


def test_user_already_logged_decorator(client):
    login_user(client)

    response = client.get('/login', follow_redirects=True)
    assert "Usuário já logado!" in response.text
