from datetime import datetime

import pytz
from flask import redirect, request, session, url_for
from flask_admin.contrib.sqla import ModelView
from werkzeug.security import check_password_hash, generate_password_hash

from .extension import adm, db, jwt

session_db = db.session


class User(db.Model):
    __tablename__ = 'user'

    id = db.Column('id', db.Integer, primary_key=True)
    google_id = db.Column('google_id', db.String)
    username = db.Column('username', db.String)
    email = db.Column('email', db.String, unique=True)
    password = db.Column('password', db.String)
    has_permitions = db.Column('has_perm', db.Boolean, default=False)

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
            'id': self.id,
            'username': self.username,
            'email': self.email,
        }


@jwt.user_identity_loader
def user_identity_lookup(user):
    return user


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data['sub']
    return User.query.filter_by(id=identity).one_or_none()


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
        'user.id', ondelete="CASCADE"), unique=True)

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


# Admin:

class CurrencyTrackModelView(ModelView):
    def is_accessible(self):
        user_is_logged = True if "user" in session else False
        if not user_is_logged:
            return False
        user = session_db.query(User).filter_by(id=session['user']).first()
        if user and user.has_permitions is True:
            return True
        return False

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('main.login_view', next=request.url))


adm.add_view(CurrencyTrackModelView(User, session_db))
adm.add_view(CurrencyTrackModelView(CurrencyValues, session_db))
