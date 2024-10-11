import os
import pathlib
from functools import wraps

import google.auth.transport.requests
import requests
from flask import Blueprint, abort, flash, redirect, request, session
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from models import OAuth, User, session_db
from pip._vendor import cachecontrol
from utils import decrypt_token, encrypt_token

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
    def wrapper(*args, **kwargs):
        if 'google_id' not in session:
            return abort(401)
        return function()
    return wrapper


def token_is_required(function):
    """
    Decorator that validates the access token provided in the request headers
    via the Google API. If the access token is invalid, it attempts to obtain
    a new one using the associated refresh token.

    - If the access token is valid, the request proceeds as normal.
    - If the access token is invalid but the refresh token is valid, a new
      access token is fetched and the request proceeds.
    - If both the access token and refresh token are invalid, the user is
      redirected to the login page to re-authenticate.

    This ensures that API requests are always authenticated with a valid token.
    """
    @wraps(function)
    def wrapper(*args, **kwargs):
        # Check if the access token is present in the Authorization header
        access_token = request.headers.get(
            'Authorization')
        # If no access token is found, respond with 401 Unauthorized error
        if access_token is None:
            return abort(401)

        key_access_token = access_token.replace('Bearer ', '')

        # Verify the access token using Google's API
        token_info = verify_access_token(key_access_token)

        # If the token is invalid, try to generate a new token
        if not token_info:
            try:
                # Search for the associated refresh token with de access token
                oauth = get_oauth(key_access_token)

                # Decrypt the stored refresh token from the database
                decrypted_refresh_token = decrypt_token(
                    oauth.refresh_token)  # type: ignore
                ...

                # Use the decrypted refresh token to generate
                # a new access token
                new_token = refresh_token(decrypted_refresh_token)
                if not new_token:
                    flash(
                        "Sua sessão foi encerrada, faça login novamente "
                        "para continuar", "error")
                    oauth.refresh_token = None  # type: ignore
                    oauth.access_token = None  # type: ignore
                    session_db.commit()
                    return redirect('/')

                # If a new access token was successfully generated,
                # update the database
                access_token = new_token['access_token']  # type: ignore
                if new_token:
                    oauth.access_token = access_token  # type: ignore
                    session_db.commit()
            except Exception as e:
                return {
                    "Error": f"The server could not refresh the token: {e}"}

        # Fetch the OAuth record again to get user info
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

    access_token = credentials.token
    refresh_token = encrypt_token(credentials.refresh_token)
    if not oauth:
        oauth = OAuth(
            access_token=access_token,
            refresh_token=refresh_token,
            user_id=user.id  # type: ignore
        )
        session_db.add(oauth)
        session_db.commit()
    else:
        oauth.access_token = access_token
        oauth.refresh_token = refresh_token
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
