from .test_user_and_authentication import create_user, generate_user_data


def generate_tokens(client):
    user = create_user()
    user_data = {
        "email": user.email,
        "password": "Password1"
    }
    response = client.post(
        "/api/create_token", json=user_data, follow_redirects=True)
    tokens = {
        "access_token": response.json['access_token'],
        "refresh_token": response.json['refresh_token']
    }
    return tokens


def test_api_user_create_form_errors_email_and_username(client):
    user_data = generate_user_data(email="invalid_email", username="user")
    response = client.post("/api/user", json=user_data, follow_redirects=True)
    assert b"Invalid email format" in response.data
    assert b"The username must have at least 5 characters" in response.data
    assert response.status_code == 400

    create_user()
    user_data['email'] = "test@email.com"
    response = client.post("/api/user", json=user_data, follow_redirects=True)
    assert b"A user with that email already exist" in response.data
    assert response.status_code == 400


def test_api_user_create_form_errors_password(client):
    user_data = generate_user_data(password="invalidPassword")
    response = client.post("/api/user", json=user_data, follow_redirects=True)
    assert b"The password must contain at least one " in response.data
    assert response.status_code == 400

    user_data = generate_user_data(repeat_password="notequalpassword")
    response = client.post("/api/user", json=user_data, follow_redirects=True)
    assert b"The passwords need to match" in response.data
    assert response.status_code == 400


def test_api_user_create_form_fields_are_required(client):
    user_data = generate_user_data()
    for key, value in user_data.items():
        user_data[key] = ""
        response = client.post(
            "/api/user", json=user_data, follow_redirects=True)
        assert b"This field is required" in response.data


def test_api_user_create_succesfully(client):
    user_data = generate_user_data()
    response = client.post("/api/user", json=user_data, follow_redirects=True)
    assert response.status_code == 201
    assert response.json['id'] == 1


def test_api_tokens_create_view_has_to_be_post(client):
    response = client.get("/api/create_token")
    assert response.status_code == 405


def test_api_tokens_create_fields_are_required(client):
    user = create_user()
    user_data = {
        "email": user.email,
        "password": "Password1"
    }
    for key, value in user_data.items():
        user_data[key] = ""
        response = client.post(
            "/api/create_token", json=user_data, follow_redirects=True)
        assert b"This field is required" in response.data


def test_api_tokens_create_successfully(client):
    user = create_user()
    user_data = {
        "email": user.email,
        "password": "Password1"
    }
    response = client.post(
        "/api/create_token", json=user_data, follow_redirects=True)
    assert response.status_code == 200


def test_api_get_user_jwt_is_required(client):
    create_user()
    response = client.get('/api/user', follow_redirects=True)
    assert response.status_code == 401


def test_api_get_user_infos_with_success(client):
    tokens = generate_tokens(client)
    response = client.get(
        "/api/user", headers={
            "Authorization": f"Bearer {tokens['access_token']}"
        }, follow_redirects=True)
    assert b"test@email.com" in response.data
    assert response.status_code == 200


def test_api_patch_user_fields_are_optitional(client):
    tokens = generate_tokens(client)
    response = client.patch(
        "/api/user", headers={
            "Authorization": f"Bearer {tokens['access_token']}"
        }, json={"username": "TestUser"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"TestUser" in response.data

    response = client.patch(
        "/api/user", headers={
            "Authorization": f"Bearer {tokens['access_token']}"
        }, json={"email": "test2@email.com"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"test2@email.com" in response.data
