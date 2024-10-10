import os
import pathlib
from functools import wraps

import google.auth.transport.requests
import requests
from flask import Blueprint, abort, redirect, request, session
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from models import User, session_db
from pip._vendor import cachecontrol

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
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
    @wraps(function)
    def wrapper(*args, **kwargs):
        access_token = request.headers.get(
            'Authorization')  # Pegue o token do header
        if access_token is None:
            # Não autorizado se 'Authorization' não estiver presente
            return abort(401)

        # Verifica o access_token com os servidores do Google
        token_info = verify_access_token(access_token.replace('Bearer ', ''))
        if not token_info:
            # Se o token não for válido, aborta com 401
            return abort(401)

        return function(*args, **kwargs)

    return wrapper


def verify_access_token(access_token):
    """Verifica o access_token com o Google OAuth 2.0"""
    url = f"https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={
        access_token}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()  # Retorna os dados do token se válido
    return None  # Token inválido


@auth_pb.route('/login')
def login():
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
            email=id_info["email"]
        )
        session_db.add(user)
        session_db.commit()

    session['google_id'] = id_info.get('sub')
    session['name'] = id_info.get('name')
    return redirect('/protected_area')


@auth_pb.route("/protected_area")
@login_is_required
def protected_area():
    return f"Hello {session['name']}! <br/> <a href='/logout'>" \
        "<button>Logout</button></a>"


@auth_pb.route('/logout')
def logout():
    session.clear()
    return redirect("/")
