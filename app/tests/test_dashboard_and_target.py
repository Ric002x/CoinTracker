from ..extension import db
from ..models import CurrencyValues
from .test_user_and_authentication import login_user


def create_currency_obj():
    currency = CurrencyValues(
        value_dollar=5.6000
    )
    db.session.add(currency)
    db.session.commit()
    return currency


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


def test_target_update_succesfully(client):
    login_user(client)
    client.post("/user/dashboard", data={
        "value": "1"})
    response = client.post("/user/dashboard", data={
        "value": "1"
    }, follow_redirects=True)
    assert "valor atualizado com sucesso" in response.text


def test_target_delete_redirect_if_not_post(client):
    login_user(client)
    response = client.get('/user/dashboard/target-delete')
    assert response.status_code == 302
    assert "/user/dashboard" in response.location


def test_target_delete_error_if_no_target(client):
    login_user(client)
    response = client.post(
        '/user/dashboard/target-delete', follow_redirects=True)
    assert "Nenhum valor para deletar" in response.text


def test_target_delete_succesfully(client):
    login_user(client)
    client.post("/user/dashboard", data={
        "value": "1"})
    response = client.post(
        '/user/dashboard/target-delete', follow_redirects=True)
    assert "Valor deletado" in response.text


def test_currency_show_minutes_after_creation_in_template(client):
    login_user(client)
    currency = create_currency_obj()

    response = client.get('/user/dashboard')
    assert f"{currency.value_dollar}" in response.text
    assert "minutos" in response.text
