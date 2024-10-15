from flask import Blueprint, render_template

main = Blueprint('main', __name__)


@main.route('/')
def home():
    return render_template('pages/home.html')


@main.route('/login')
def login_page():
    return render_template('pages/login.html')
