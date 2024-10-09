import os

from flask import Flask, redirect, url_for
from flask_dance.contrib.google import google, make_google_blueprint
from views import main

app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersekrit")
app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.environ.get(
    "GOOGLE_OAUTH_CLIENT_SECRET")
google_bp = make_google_blueprint(scope=["profile", "email"])


app.register_blueprint(google_bp)

app.register_blueprint(main)


@app.route('/login')
def login_start():
    if not google.authorized:
        return redirect(url_for("google.login"))
    resp = google.get('/oauth2/v1/userinfo')
    assert resp.ok, resp.text
    return "You are {email} on Google".format(email=resp.json()["email"])


if __name__ == "__main__":
    app.run(debug=False)
