from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def create_app():
    import os

    from dotenv import load_dotenv
    from flask_restful import Api

    from app.api.auth import auth_pb_api
    from app.api.views import Alerts

    from .auth import auth_pb
    from .views import main

    app = Flask(__name__)
    api = Api(app)

    load_dotenv()

    DATABASE_USER = os.environ.get("DATABASE_USER")
    DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD")
    DATABASE_HOST = os.environ.get("DATABASE_HOST")
    DATABASE_DB = os.environ.get("DATABASE_DB")
    USE_POSTGRESQL = os.environ.get("USE_POSTGRESQL", "0") == "1"

    if USE_POSTGRESQL:
        app.config["SQLALCHEMY_DATABASE_URI"] = \
            "postgresql+psycopg2://" \
            f"{DATABASE_USER}:" \
            f"{DATABASE_PASSWORD}" \
            f"@{DATABASE_HOST}:5432/{DATABASE_DB}"
    else:
        app.config["SQLALCHEMY_DATABASE_URI"] = (
            str(os.environ.get("DATABASE_SQLITE")))

    db.init_app(app)

    # from flask_cors import CORS
    # CORS(app, origins=['http://127.0.0.1:5500'])

    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersekrit")
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"

    app.register_blueprint(main)
    app.register_blueprint(auth_pb)
    app.register_blueprint(auth_pb_api)
    api.add_resource(Alerts, "/api/alert/")

    # error templates

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('pages/errors/404.html'), 404

    return app
