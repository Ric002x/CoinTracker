from sqlalchemy import (Column, DateTime, Float, ForeignKey, Integer, String,
                        create_engine, func)
from sqlalchemy.orm import declarative_base, sessionmaker

db = create_engine('sqlite:///mydatabase.db')
Session = sessionmaker(bind=db)
session_db = Session()

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column('id', Integer, primary_key=True, autoincrement=True)
    google_id = Column('google_id', String)
    username = Column('username', String)
    email = Column('email', String, unique=True)

    def __init__(self, google_id, username, email):
        self.google_id = google_id
        self.username = username
        self.email = email

    def __str__(self):
        return f'{self.username}'

    def to_dict(self):
        return {
            'username': self.username,
            'google_id': self.google_id,
            'email': self.email
        }


class OAuth(Base):
    __tablename__ = 'user_tokens'

    id = Column('id', Integer, primary_key=True, autoincrement=True)
    refresh_token = Column('refresh_token', String)
    user_id = Column('user_id', ForeignKey('user.id', ondelete="CASCADE"))

    def __init__(self, refresh_token, user_id):
        self.refresh_token = refresh_token
        self.user_id = user_id


class CurrencyValues(Base):
    __tablename__ = 'currency_values'

    id = Column('id', Integer, primary_key=True, autoincrement=True)
    value_dollar = Column('value_dollar', Float)
    date = Column('date', DateTime, default=func.now())

    def __init__(self, value_dollar):
        self.value_dollar = value_dollar


class TargetValue(Base):
    __tablename__ = 'target_value'

    id = Column('id', Integer, primary_key=True, autoincrement=True)
    value = Column('value', Float)
    user_id = Column('user_id', ForeignKey('user.id', ondelete="CASCADE"))

    def __init__(self, value, user_id):
        self.value = value
        self.user_id = user_id

    def __str__(self):
        return f'{self.value}'


Base.metadata.create_all(bind=db)
