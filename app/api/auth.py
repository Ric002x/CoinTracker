import os
import pathlib
from functools import wraps

import google.auth.transport.requests
import requests
from flask import Blueprint, abort, jsonify, request, session
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol

from app.base.models import OAuth, User, session_db
from app.base.utils import decrypt_token, encrypt_token

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

auth_pb_api = Blueprint('auth_api', __name__)


def token_is_required(function):
    """
    Decorator that validates the access token provided in the request headers
    via the Google API.

    - If the access token is valid, the request proceeds as normal. Otherwise,
    if the token is invalid, return status_code 401 instead.

    This ensures that API requests are always authenticated with a valid token.
    """
    @wraps(function)
    def wrapper(*args, **kwargs):
        # Check if the access token is present in the Authorization header
        access_token = request.headers.get(
            'Authorization')
        # If no access token is found, respond with 401 Unauthorized error
        if access_token is None:
            return jsonify(
                {"Authentication Error":
                 "No access token was given in the header"}), 401

        key_access_token = access_token.replace('Bearer ', '')

        # Verify the access token using Google's API
        token_info = verify_access_token(key_access_token)

        # If the token is invalid, try to generate a new token
        if not token_info:
            return jsonify(
                {"Authorization Error":
                 "Access token is invalid or has expired"}), 401
        return function(*args, **kwargs)

    return wrapper


def verify_access_token(access_token):
    """
    Validates the access token via Google API
    """
    url = f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={
        access_token}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    return False


def refresh_token(refresh_token):
    """
    Generates a new access token using the provided refresh token.

    This function is called when the user's access token has expired or becomes
    invalid. It sends a request to Google's OAuth 2.0 token endpoint,
    exchanging the refresh token for a new access token.

    Args:
        refresh_token (str): The refresh token associated with
        the user's session.

    Returns:
        dict: A dictionary containing the new access token and other
        information if the request is successful (HTTP 200).
        None: If the request fails (non-200 status code).
    """
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


@auth_pb_api.route('/api/refresh-token', methods=["POST"])
def refresh_token_route():
    """
    Refreshes the user's access token using the stored refresh token.

    This view checks if the user is authenticated by looking for their
    Google ID in the request cookies. If authenticated, it retrieves the
    associated refresh token from the database and attempts to generate
    a new access token. The new access token is then stored in a cookie.

    Returns:
        Response: A JSON response indicating the success or failure of the
        token refresh operation, along with the appropriate HTTP status code.

        - On success, returns a 200 status code with a success message.
        - If the user is not authenticated, returns a 401 status code with an
          error message.
        - If the user is not found in the database, returns a 404 status code.
        - If no refresh token is found for the user, returns a 404 status code.
        - If the token refresh fails, returns a 401 status code with an
          error message.
    """
    google_id = request.cookies.get('google_id')
    if not google_id:
        return jsonify({"Error": "User not authenticated"}), 401

    user = session_db.query(User).filter_by(google_id=google_id).first()
    if not user:
        return jsonify({"Error": "User not found"}), 404

    user_oauth = session_db.query(OAuth).filter_by(user_id=user.id) \
        .first()
    if not user_oauth:
        return jsonify({"Error": "No refresh token found"}), 404

    decrypted_refresh_token = decrypt_token(user_oauth.refresh_token)

    new_token = refresh_token(decrypted_refresh_token)
    if not new_token:
        return jsonify({"Error": "Failed to refresh token"}), 401

    user_oauth.access_token = new_token['access_token']
    session_db.commit()

    response = jsonify({"Success": "Token refreshed successfully"})
    response.set_cookie(
        'jwt', new_token['access_token'], httponly=True, secure=True)
    return response


@auth_pb_api.route('/api/login')
def login():
    authorization_url, state = flow.authorization_url(prompt='consent')
    session['state'] = state
    if not authorization_url and not state:
        return {"error": "User didn't consent the authentication"}, 303
    return authorization_url, state


@auth_pb_api.route('/api/callback')
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

    access_token = credentials.token
    refresh_token = encrypt_token(credentials.refresh_token)

    response = jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token
    }), 200
    return response
