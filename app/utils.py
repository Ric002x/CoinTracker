# Using Criptografy
import os

from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

key = str(os.environ.get('FERNET_SECRET_KEY'))
cipher_suite = Fernet(key)


def encrypt_token(token):
    return cipher_suite.encrypt(token.encode('utf-8'))


def decrypt_token(token):
    return cipher_suite.decrypt(token).decode('utf-8')
