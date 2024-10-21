import os
import pathlib

import google.auth.transport.requests
import requests
from flask import Blueprint, jsonify, redirect, request, session
from flask_jwt_extended import create_access_token, create_refresh_token
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol

from ..models import User, session_db

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
client_secret_file = os.path.join(
    pathlib.Path(__file__).parent.parent, "client_secret.json"
)

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secret_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://localhost/api/callback"
)

oauth_api_pb = Blueprint('api_oauth', __name__)


@oauth_api_pb.route('/api/login/oauth')
def login_oauth():
    authorization_url, state = flow.authorization_url(prompt='consent')
    session['state'] = state
    return redirect(authorization_url)


@oauth_api_pb.route('/api/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)
    if not session['state'] == request.args['state']:
        return jsonify({
            "msg": "error in session states"
        })

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

    user = session_db.query(User).filter_by(email=id_info['email']).first()

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

    user = User.query.filter_by(email=id_info['email']).one_or_none()

    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)

    tokens = {
        "access_token": access_token,
        "refresh_token": refresh_token
    }

    return jsonify(tokens)
