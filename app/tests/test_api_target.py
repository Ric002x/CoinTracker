from .test_api_user_and_authentication import create_user, generate_tokens


def create_target(client, token):
    target = client.post('/api/target', headers={
        "Authorization": f"Bearer {token}"
    }, json={"value": 5.6}, follow_redirects=True)
    return target.json


def test_api_target_get_jwt_is_required(client):
    response = client.get('/api/target', follow_redirects=True)
    assert response.status_code == 401


def test_api_target_get_user_has_to_create_a_target(client):
    tokens = generate_tokens(client)
    response = client.get('/api/target', headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    }, follow_redirects=True)
    assert response.status_code == 400
    assert b"No target created by user" in response.data


def test_api_target_post_jwt_is_required(client):
    response = client.post(
        '/api/target', json={"value": -1}, follow_redirects=True)
    assert response.status_code == 401


def test_api_target_post_form_errors(client):
    tokens = generate_tokens(client)
    response = client.post('/api/target', headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    }, json={"value": -1}, follow_redirects=True)
    assert response.status_code == 400
    assert b"The value has to be positive" in response.data

    response = client.post('/api/target', headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    }, json={"value": "a"}, follow_redirects=True)
    assert response.status_code == 400
    assert b"A numeric value is required" in response.data

    response = client.post('/api/target', headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    }, json={"value": ""}, follow_redirects=True)
    assert response.status_code == 400
    assert b"This field is required" in response.data


def test_api_target_post_successfull_create_target(client):
    tokens = generate_tokens(client)
    response = client.post('/api/target', headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    }, json={"value": 5.6}, follow_redirects=True)
    assert response.status_code == 201
    assert b"5.6" in response.data


def test_api_target_post_user_can_only_haver_one_target_value(client):
    tokens = generate_tokens(client)
    client.post('/api/target', headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    }, json={"value": 5.6}, follow_redirects=True)

    second_target = client.post('/api/target', headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    }, json={"value": 5.6}, follow_redirects=True)

    assert second_target.status_code == 400
    assert b"failed to create. this user already has" in second_target.data


def test_api_target_get_return_user_target(client):
    tokens = generate_tokens(client)
    target = create_target(client, tokens['access_token'])

    response = client.get('/api/target', headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    }, follow_redirects=True)
    assert response.status_code == 200
    assert target['value'] == response.json.get("value")


def test_api_target_patch_form_errors(client):
    tokens = generate_tokens(client)
    create_target(client, tokens['access_token'])

    response = client.patch('/api/target', headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    }, json={"value": -1}, follow_redirects=True)
    assert response.status_code == 400
    assert b"The value has to be positive" in response.data

    response = client.patch('/api/target', headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    }, json={"value": "a"}, follow_redirects=True)
    assert response.status_code == 400
    assert b"A numeric value is required" in response.data

    response = client.patch('/api/target', headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    }, json={"value": ""}, follow_redirects=True)
    assert response.status_code == 400
    assert b"This field is required" in response.data


def test_api_target_patch_no_target_to_update(client):
    tokens = generate_tokens(client)

    response = client.patch('/api/target', headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    }, json={"value": 5}, follow_redirects=True)
    assert response.status_code == 400
    assert b"no target to update" in response.data


def test_api_target_patch_update_successfully(client):
    tokens = generate_tokens(client)
    create_target(client, tokens['access_token'])

    response = client.patch('/api/target', headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    }, json={"value": 6}, follow_redirects=True)
    assert response.status_code == 200
    assert 6 == response.json.get('value')


def test_api_target_delete_jwt_required(client):
    response = client.delete('/api/target', follow_redirects=True)
    assert response.status_code == 405


def test_api_target_delete_no_target_found(client):
    tokens = generate_tokens(client)

    response = client.delete('/api/target', headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    }, follow_redirects=True)
    assert response.status_code == 400
    assert b"No target found" in response.data


def test_api_target_delete_with_success(client):
    tokens = generate_tokens(client)
    create_target(client, tokens['access_token'])

    response = client.delete('/api/target', headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Target deleted successful" in response.data
