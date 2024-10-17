import datetime

from flask import Blueprint, flash, redirect, session

from .auth import get_user, render, render_restricted, user_alredy_logged
from .forms import AlertFormPOST, LoginForm, RegisterForm
from .models import CurrencyValues, TargetValue, User, session_db

main = Blueprint('main', __name__)


def parse_time(time_str):
    hours, minutes, seconds = map(float, time_str.split(':'))
    return minutes


@main.route('/')
def home():
    return render('pages/home.html')


@main.route('/register', methods=["GET", "POST"])
@user_alredy_logged
def register_view():
    form = RegisterForm()
    if form.validate_on_submit():
        data = form.data
        user = User(
            username=data['username'],
            email=data['email'],
            google_id=None,
            password=None
        )
        user.set_password(data['password'])
        session_db.add(user)
        session_db.commit()
        flash("Usuário cadastrado! Faça login para continuar.", "success")
        redirect('/login')

    context = {
        'form': form
    }
    return render('pages/register.html', **context)


@main.route('/login', methods=["GET", "POST"])
@user_alredy_logged
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        user = session_db.query(User).filter_by(email=data['email']).first()
        if user:
            try:
                user.check_password(data['password']) if user else None
            except Exception:
                flash("E-mail ou senha inválidos", "error")
                return redirect('/login')
            session['user'] = user.id
            session['name'] = user.username
            flash("Login realizado com sucesso", "success")
            return redirect('/')
    elif not form.validate_on_submit():
        flash("Falha no login", "error")

    context = {
        'form': form
    }
    return render('pages/login.html', **context)


@main.route('/dashboard', methods=["GET", "POST"])
def user_dashboard():
    """
    This view function handles both GET and POSTrequests for the user
    dashboard.

    GET request:
    - Renders a dashboard page that includes the latest currency value
    (e.g., USD exchange rate) and a form allowing the user to set a
    target value.

    POST request:
    - Handles form submission to either create or update the user's target
    value for the currency.

    Context variables passed to the template:
    - `currency`: The latest currency value retrieved from the database.
    - `minutes`: The time difference, in minutes, since the last currency
    value update.
    - `form`: The form for submitting or updating the user's target value.
    - `user_target`: The target value the user has set (if any).

    Returns:
        - A rendered dashboard page with the form and current currency
        data (for GET).
        - Redirects to the dashboard page upon successful form submission
        (for POST).
    """
    form = AlertFormPOST()
    user = get_user()
    target = session_db.query(TargetValue).filter_by(
        user_id=user.id if user else None).first()

    # If user submit the form:
    if form.validate_on_submit():
        value = form.value.data
        if not target:
            target = TargetValue(
                value=value,
                user_id=user.id if user else None
            )
            session_db.add(target)
            session_db.commit()
            flash("Valor enviado", "success")
            return redirect('/dashboard')

        target.value = value
        session_db.commit()
        flash("valor atualizado com sucesso", "success")
    if not form.validate_on_submit():
        redirect('/dashboard')

    currency = session_db.query(CurrencyValues).order_by(
        CurrencyValues.id.desc()
    ).first()
    if currency:
        last_update = currency.date if currency else None

        actual_date = datetime.datetime.now()
        if last_update is not None and actual_date is not None:
            sub = actual_date - last_update
            minutes = parse_time(f"{sub}")
    context = {
        'currency': currency.to_dict() if currency else None,
        'minutes': str(minutes).replace('.0', '') if minutes else None,
        'form': form,
        'user_target': target.value if target else None
    }
    return render_restricted(
        'pages/dashboard.html', **context)
