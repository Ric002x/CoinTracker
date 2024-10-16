import os
import pathlib
from functools import wraps

import google.auth.transport.requests
import requests
from flask import Blueprint, abort, flash, redirect
from flask import render_template as flask_render_template
from flask import request, session
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol

from .models import User, session_db

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
client_secret_file = os.path.join(
    pathlib.Path(__file__).parent, "client_secret.json"
)

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secret_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://localhost/callback"
)

auth_pb = Blueprint('auth', __name__)


def login_is_required(function):
    """
    Decorator that checks if the user is logged in by verifying if 'google_id'
    exists in the Flask session.

    The 'google_id' is stored in the session when a user logs in successfully.
    This is typically done by caching the user's session after authenticating
    with Google. If 'google_id' is not present in the session, it implies that
    the user is not logged in, and appropriate actions (e.g., redirect to
    login) should be taken.
    """
    def wrapper():
        if 'user' not in session:
            flash("Usuário não logado. Faça login para continar", "error")
            return redirect('/login')
        return function()
    return wrapper


def render(template, *args, **kwargs):
    if 'user' in session:
        logged_user = session_db.query(User).filter_by(
            id=session['user']).first()
        if not logged_user:
            flash(
                "Usuário não encontrado na sessão. Por favor,"
                " faça login novamente", "error")
        context = {'user': logged_user.to_dict() if logged_user else None}
        return flask_render_template(
            template, *args, **kwargs, **context)

    return flask_render_template(template, *args, **kwargs)


def render_restricted(template, *args, **kwargs):
    if 'user' not in session:
        flash("É necessário estar logado para acessar este recurso", "warning")
        return redirect('/login')

    logged_user = session_db.query(User).filter_by(
        id=session['user']).first()
    context = {'user': logged_user.to_dict() if logged_user else None}
    return flask_render_template(
        template, *args, **kwargs, **context)


def get_user():
    user = session_db.query(User).filter_by(
        id=session['user']).first()
    return user


def user_alredy_logged(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if 'user' in session:
            flash("Usuário já logado!", "error")
            return redirect('/')
        return function(*args, **kwargs)
    return wrapper


@auth_pb.route('/login/oauth')
def login_oauth():
    if 'user' in session:
        return {"Error": "Usuário já logado"}
    authorization_url, state = flow.authorization_url(prompt='consent')
    session['state'] = state
    return redirect(authorization_url)


@auth_pb.route('/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)
    if not session['state'] == request.args['state']:
        abort(500)

    credentials = flow.credentials

    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)  # type: ignore
    token_request = google.auth.transport.requests.Request(
        session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,  # type: ignore
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    user = session_db.query(User).filter_by(google_id=id_info['sub']).first()

    if not user:
        user = User(
            google_id=id_info["sub"],  # type: ignore
            username=id_info["name"],
            email=id_info["email"],
            password=None,
        )
        session_db.add(user)
        session_db.commit()
    elif user and user.google_id is None:
        user.google_id = id_info["sub"]
        session_db.commit()

    session['google_id'] = id_info.get('sub')
    session['name'] = id_info.get('name')
    session['user'] = user.id

    flash("Login feito com sucesso", "success")
    return redirect('/')


@auth_pb.route('/logout')
def logout():
    if 'user' in session:
        session.clear()
        flash("Logout feito com sucesso", "success")
        return redirect('/')
    else:
        flash("Não há usuário logado", "error")
        return redirect('/')
