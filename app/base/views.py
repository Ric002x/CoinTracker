from flask import Blueprint, render_template

from .auth import load_user

# from .models import User, session_db

main = Blueprint('main', __name__)

# logged_user = session_db.query(User).filter_by(
#     google_id=session['google_id']).first()


@main.route('/')
def home():
    user = load_user()
    return render_template('pages/home.html',
                           user=user.to_dict() if user else None)


@main.route('/login')
def login_page():
    return render_template('pages/login.html')
