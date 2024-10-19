from flask_jwt_extended import JWTManager
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy

api = Api()
jwt = JWTManager()
db = SQLAlchemy()
