# Using Criptografy
import os
import time
from threading import Thread

import requests
import schedule
import sendgrid
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from sendgrid.helpers.mail import Content, Email, Mail, To

from .models import CurrencyValues, TargetValue, User, session_db

load_dotenv()

key = str(os.environ.get('FERNET_SECRET_KEY'))
cipher_suite = Fernet(key)


def encrypt_token(token):
    return cipher_suite.encrypt(token.encode('utf-8'))


def decrypt_token(token):
    return cipher_suite.decrypt(token).decode('utf-8')


# SendGrid - SendingEmail to users
def send_email(value: float, users: list) -> None:
    """ # noqa: E501
    Sends an email notification to a list of users about the current dollar value.

    Args:
        value (float): The current dollar value to include in the email.
        users (list): A list of user objects to send the notification to. Each user
                      should have `email` and `username` attributes.

    Returns:
        None
    """
    sg = sendgrid.SendGridAPIClient(api_key=os.environ.get("SENDGRID_API_KEY"))
    from_email = Email("ricvenicius@gmail.com")
    subject = "O Dolár alcançou o valor desejado por você!!"
    content = Content(
        "text/plain", "O valor do dólar atualmente é de "
        f"R$ {str(value).replace(".", ",")}")
    for user in users:
        to_email = To(email=user.email, name=user.username)
        mail = Mail(from_email, to_email, subject, content)

        mail_json = mail.get()

        sg.client.mail.send.post(request_body=mail_json)  # type: ignore


# Schedule for CurrencyGet
def get_currency():
    """
    This function uses the requests library to get the current dollar value
    through an external API named AwesomeAPI using HTTP GET, and save that
    value in the database.

    This function will also search in the table 'targetvalues', values that is
    equal or lower than the current dollar value. The 'targetvalue' table has
    a column named user_id, and a notification email will be send to those user
    using the function 'send_email'.
    """
    from run import app
    with app.app_context():
        url = "https://economia.awesomeapi.com.br/json/last/USD-BRL"
        response = requests.get(url)
        data = response.json()

        try:
            current_value = data['USDBRL']['bid']
            values_db = CurrencyValues(value_dollar=current_value)
            session_db.add(values_db)
            session_db.commit()
            print("Dolar atualizado com sucesso")

            targeted_list = session_db.query(TargetValue).filter(
                # type: ignore
                current_value <= TargetValue.value).all()  # type: ignore

            user_ids = [target.user_id for target in targeted_list]
            users = session_db.query(User).filter(User.id.in_(user_ids)).all()

            if len(users) > 0:
                try:
                    send_email(value=current_value, users=users)
                except Exception as e:
                    print(f"Erro no envio de mesagens: {e}")

        except Exception as e:
            print(f"Não foi possível atualizar o banco de dados: {e}")


def setup_schedule():
    """
    This function setups the frequency that the dollar will be obtained through
    the API
    """
    schedule.every(30).minutes.do(get_currency)
    while True:
        print("Verificando execuções pendentes...")
        schedule.run_pending()
        time.sleep(60)


def start_schedule():
    """ # noqa: E501
    Starts the scheduled tasks in a separate thread.

    This function spawns a new thread to run the `setup_schedule` function, allowing
    the scheduling system to run in the background without blocking the main application
    thread.

    Returns:
        None
    """
    scheduler_thread = Thread(target=setup_schedule)
    scheduler_thread.daemon = True
    scheduler_thread.start()
