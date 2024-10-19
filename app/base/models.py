from datetime import datetime

import pytz
from werkzeug.security import check_password_hash, generate_password_hash

from app.base import db

session_db = db.session


class User(db.Model):
    __tablename__ = 'user'

    id = db.Column('id', db.Integer, primary_key=True)
    google_id = db.Column('google_id', db.String)
    username = db.Column('username', db.String)
    email = db.Column('email', db.String, unique=True)
    password = db.Column('senha', db.String)

    def __init__(self, google_id, username, email, password):
        self.google_id = google_id
        self.username = username
        self.email = email
        self.password = password

    def __str__(self):
        return f'{self.username}'

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)  # type: ignore

    def to_dict(self):
        return {
            'username': self.username,
            'google_id': self.google_id,
            'email': self.email
        }


class OAuth(db.Model):
    __tablename__ = 'user_tokens'

    id = db.Column('id', db.Integer, primary_key=True, autoincrement=True)
    refresh_token = db.Column('refresh_token', db.String)
    user_id = db.Column('user_id', db.ForeignKey(
        'user.id', ondelete="CASCADE"))

    def __init__(self, refresh_token, user_id):
        self.refresh_token = refresh_token
        self.user_id = user_id


class CurrencyValues(db.Model):
    __tablename__ = 'currency_values'

    id = db.Column('id', db.Integer, primary_key=True, autoincrement=True)
    value_dollar = db.Column('value_dollar', db.Float)
    date = db.Column('date', db.DateTime,
                     default=lambda: datetime.now(pytz.timezone(
                         'America/Fortaleza')))

    def __init__(self, value_dollar):
        self.value_dollar = value_dollar

    def to_dict(self):
        return {
            'id': self.id,
            'value_dollar': self.value_dollar,
            'date': self.date
        }


class TargetValue(db.Model):
    __tablename__ = 'target_value'

    id = db.Column('id', db.Integer, primary_key=True, autoincrement=True)
    value = db.Column('value', db.Float)
    user_id = db.Column('user_id', db.ForeignKey(
        'user.id', ondelete="CASCADE"))

    def __init__(self, value, user_id):
        self.value = value
        self.user_id = user_id

    def __str__(self):
        return f'{self.value}'

    def to_dict(self):
        return {
            "id": self.id,
            "value": self.value,
            "user": self.user_id
        }
