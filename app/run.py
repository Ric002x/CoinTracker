import os
import pathlib

import google.auth.transport.requests
import requests
from flask import Flask, abort, redirect, request, session
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from models import User, session_db
from pip._vendor import cachecontrol
from views import main

app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersekrit")
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"

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


def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)
        else:
            return function()

    return wrapper


@app.route('/login')
def login():
    authorization_url, state = flow.authorization_url(prompt='consent')
    session['state'] = state
    return redirect(authorization_url)


@app.route('/callback')
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


@app.route("/protected_area")
@login_is_required
def protected_area():
    return f"Hello {session['name']}! <br/> <a href='/logout'>" \
        "<button>Logout</button></a>"


@app.route('/logout')
def logout():
    session.clear()
    return redirect("/")


app.register_blueprint(main)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80, debug=True)
