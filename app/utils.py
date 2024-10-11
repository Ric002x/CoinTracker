# Using Criptografy
import os
import time
from threading import Thread

import requests
import schedule
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from models import CurrencyValues, session_db

load_dotenv()

key = str(os.environ.get('FERNET_SECRET_KEY'))
cipher_suite = Fernet(key)


def encrypt_token(token):
    return cipher_suite.encrypt(token.encode('utf-8'))


def decrypt_token(token):
    return cipher_suite.decrypt(token).decode('utf-8')


# Creating Schedule
def get_currency():
    from run import app
    with app.app_context():
        url = "https://economia.awesomeapi.com.br/json/last/USD-BRL"
        response = requests.get(url)
        data = response.json()

        try:
            value_dollar = data['USDBRL']['bid']
            values_db = CurrencyValues(value_dollar=value_dollar)
            session_db.add(values_db)
            session_db.commit()
            print("Dolar atualizado com sucesso")
        except Exception as e:
            print(f"Não foi possível atualizar o banco de dados: {e}")


def setup_schedule():
    schedule.every(30).minutes.do(get_currency)
    while True:
        print("Verificando execuções pendentes...")
        schedule.run_pending()
        time.sleep(60)


def start_schedule():
    scheduler_thread = Thread(target=setup_schedule)
    scheduler_thread.daemon = True
    scheduler_thread.start()
