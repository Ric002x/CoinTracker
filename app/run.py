import os

from auth import auth_pb
from flask import Flask
from flask_restful import Api
from utils import start_schedule
from views import Alerts

app = Flask(__name__)
api = Api(app)

app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersekrit")
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"

app.register_blueprint(auth_pb)
api.add_resource(Alerts, "/api/alert/")

if __name__ == "__main__":
    start_schedule()
    app.run(host='0.0.0.0', port=80, debug=False)
