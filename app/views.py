from auth import login_is_required
from flask import Blueprint, render_template
from flask_restful import Resource

main = Blueprint('main', __name__)


@main.route('/')
def home():
    return render_template('index.html')


class Alerts(Resource):
    @login_is_required
    def get():
        return {"Happy": "Message"}
