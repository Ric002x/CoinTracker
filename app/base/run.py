import os

from flask import Flask
from flask_cors import CORS
from flask_restful import Api

from app.api.auth import auth_pb_api
from app.api.views import Alerts

from .auth import auth_pb
from .utils import start_schedule
from .views import main

app = Flask(__name__)
api = Api(app)
CORS(app, origins=['http://127.0.0.1:5500'])


app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersekrit")
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"


app.register_blueprint(main)
app.register_blueprint(auth_pb)
app.register_blueprint(auth_pb_api)
api.add_resource(Alerts, "/api/alert/")


if __name__ == "__main__":
    start_schedule()
    app.run(host='0.0.0.0', port=5000, debug=False)
