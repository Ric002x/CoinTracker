import getpass

import click
from flask import Flask, render_template
from flask.cli import with_appcontext

from .config import Config
from .extension import adm, api, csrf, db, jwt


def create_app(test=False):

    from .auth import auth_pb
    from .models import User, session_db
    from .oauth.api import oauth_api_pb
    from .views.api import api_bp
    from .views.base import main

    app = Flask(__name__)

    app.config.from_object(Config)

    if test is False:
        db.init_app(app)
        csrf.init_app(app)
    api.init_app(app)
    jwt.init_app(app)
    adm.init_app(app)

    # from flask_cors import CORS
    # CORS(app, origins=['http://127.0.0.1:5500'])

    app.register_blueprint(main)
    app.register_blueprint(auth_pb)
    app.register_blueprint(api_bp)
    app.register_blueprint(oauth_api_pb)

    # error templates

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('pages/errors/404.html'), 404

    @app.cli.command("create-admin")
    @with_appcontext
    def create_admin():
        """Cria um usuário com permissões de admin."""
        # Verifica se o usuário já existe
        email = input("email: ")

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            click.echo(f"Usuário com o email {email} já existe.")
            return

        username = input("username: ")
        if not username:
            click.echo("A username is required")
            return

        password = getpass.getpass("password: ")
        if not password:
            click.echo("A password is required")
            return

        repeat_password = getpass.getpass("password: ")
        if password != repeat_password:
            click.echo("the passwords don't match")
            return

        # Cria um novo usuário com permissões de administrador
        new_user = User(
            username=username,
            email=email,
            password=None,
            google_id=None
        )
        new_user.set_password(password)
        new_user.has_permitions = True
        session_db.add(new_user)
        session_db.commit()

        click.echo(f"Usuário admin {username} criado com sucesso!")

    return app
