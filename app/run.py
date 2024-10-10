import os

from auth import auth_pb
from flask import Flask
from flask_restful import Api
from views import Alerts, main

app = Flask(__name__)
api = Api(app)

app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersekrit")
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "0"

app.register_blueprint(main)
app.register_blueprint(auth_pb)
api.add_resource(Alerts, "/api/alert/")

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80, debug=True)
