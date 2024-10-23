from .test_user_and_authentication import login_user


def test_dashboard_user_has_to_be_logged(client):
    response = client.get("/user/dashboard")
    assert response.location == '/login'
    assert response.status_code == 302


def test_dashboard_page(client):
    login_user(client)
    response = client.get("/user/dashboard")
    assert response.status_code == 200
    assert "Verifique o Valor do Dólar" in response.text


def test_target_create_form_errors(client):
    login_user(client)
    response = client.post("/user/dashboard", data={
        "value": -1
    }, follow_redirects=True)
    assert "O valor deve ser positivo" in response.text

    response = client.post("/user/dashboard", data={
        "value": ""
    }, follow_redirects=True)
    assert "Submeta um valor para salva-lo" in response.text


def test_target_create_succesfully(client):
    login_user(client)
    response = client.post("/user/dashboard", data={
        "value": "1"
    }, follow_redirects=True)
    assert "Valor enviado" in response.text
