import random

from ..extension import db
from ..models import CurrencyValues


def create_currency_values():
    for i in range(5):
        value = CurrencyValues(
            value_dollar=random.random()+5
        )
        db.session.add(value)
        db.session.commit()


def test_get_currency_list_not_found(client):
    response = client.get('/api/currency/list', follow_redirects=True)
    assert response.status_code == 500
    assert b"A value was not found" in response.data


def test_get_currency_list_has_objects(client):
    create_currency_values()
    response = client.get('/api/currency/list', follow_redirects=True)
    assert response.status_code == 200
    assert b"id" in response.data
    assert b"date" in response.data
    assert b"value" in response.data


def test_get_currency_object_not_found(client):
    response = client.get('/api/currency/latest', follow_redirects=True)
    assert response.status_code == 500
    assert b"A value was not found" in response.data


def test_get_currency_last_object(client):
    create_currency_values()
    response = client.get('/api/currency/latest', follow_redirects=True)
    assert response.status_code == 200
    assert "'id': 5" in str(response.json)
