import os
import pathlib
from functools import wraps

import google.auth.transport.requests
import requests
from flask import Blueprint, abort, redirect, request, session
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from models import OAuth, User, session_db
from pip._vendor import cachecontrol

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
    def wrapper(*args, **kwargs):
        if 'google_id' not in session:
            return abort(401)
        return function()
    return wrapper


def token_is_required(function):
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
            try:
                oauth = get_oauth(access_token.replace('Bearer ', ''))
                new_token = refresh_token(oauth.refresh_token)  # type: ignore
                access_token = new_token['access_token']  # type: ignore
                if new_token:
                    # type: ignore
                    oauth.access_token = access_token  # type: ignore
                    session_db.commit()
            except Exception as e:
                return {
                    "Error": f"The server could not refresh the token: {e}"}

        oauth = get_oauth(access_token.replace('Bearer ', ''))
        user = session_db.query(User).filter_by(
            id=oauth.user_id).first()  # type: ignore

        session['user'] = user.id  # type: ignore

        return function(*args, **kwargs)

    return wrapper


def get_oauth(token):
    oauth = session_db.query(OAuth).filter_by(access_token=token).first()
    return oauth


def verify_access_token(access_token):
    """Verifica o access_token com o Google OAuth 2.0"""
    url = f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={
        access_token}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()  # Retorna os dados do token se válido
    return False  # Token inválido


def refresh_token(refresh_token):
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET
    }

    response = requests.post(
        'https://oauth2.googleapis.com/token', data=data)

    if response.status_code == 200:
        return response.json()
    else:
        return None


@auth_pb.route('/login')
def login():
    if 'google_id' in session:
        return redirect('/protected_area')
    if request.headers.get('Authorization'):
        return redirect('/protected_area')
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

    user = session_db.query(User).filter_by(
        google_id=id_info['sub']).first()
    oauth = session_db.query(OAuth).filter_by(
        user_id=user.id).first()  # type: ignore
    if not oauth:
        oauth = OAuth(
            access_token=credentials.token,
            refresh_token=credentials.refresh_token,
            user_id=user.id  # type: ignore
        )
        session_db.add(oauth)
        session_db.commit()
    else:
        oauth.access_token = credentials.token
        oauth.refresh_token = credentials.refresh_token
        oauth.expires_at = credentials.expiry
        session_db.commit()

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
