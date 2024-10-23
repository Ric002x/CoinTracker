import datetime
from functools import wraps

from flask import Blueprint, flash, redirect
from flask import render_template as flask_render_template
from flask import request, session, url_for

from ..forms.base import (ChangePasswordForm, LoginForm, RegisterForm,
                          TargetForm, UpdateUserForm)
from ..models import CurrencyValues, TargetValue, User, session_db

main = Blueprint('main', __name__)


def parse_time(time_str):
    hours, minutes, seconds = map(float, time_str.split(':'))
    return minutes


def render(template, *args, **kwargs):
    if 'user' in session:
        logged_user = session_db.query(User).filter_by(
            id=session['user']).first()
        context = {'user': logged_user.to_dict() if logged_user else None}
        return flask_render_template(
            template, *args, **kwargs, **context)

    return flask_render_template(template, *args, **kwargs)


def login_is_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            flash("Usuário não logado. Faça login para continar", "error")
            return redirect(url_for('main.login_view'))
        user = User.query.filter_by(id=session['user']).one_or_none()
        return function(user=user, *args, **kwargs)
    return wrapper


def user_alredy_logged(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if 'user' in session:
            flash("Usuário já logado!", "error")
            return redirect('/')
        return function(*args, **kwargs)
    return wrapper


@main.route('/')
def home():
    return render('pages/home.html')


@main.route('/register', methods=["GET", "POST"])
@user_alredy_logged
def register_view():
    form = RegisterForm()

    if request.method == "POST":
        print("Um post está ocorrendo")
        if form.validate_on_submit():
            print("post validado")
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
            return redirect(url_for('main.login_view'))
        else:
            print("post inválido")

    context = {
        'form': form
    }
    return render('pages/register.html', **context)


@main.route('/login', methods=["GET", "POST"])
@user_alredy_logged
def login_view():
    form = LoginForm()

    if request.method == "POST":
        if form.validate_on_submit():
            data = form.data
            user = session_db.query(User).filter_by(
                email=data['email']).first()
            if not user:
                flash("E-mail ou senha inválidos", "error")
                return redirect(url_for('main.login_view'))

            check_password = user.check_password(
                data['password'])

            if not check_password:
                flash("E-mail ou senha inválidos", "error")
                return redirect(url_for('main.login_view'))

            session['user'] = user.id
            session['name'] = user.username
            flash("Login realizado com sucesso", "success")
            return redirect(url_for('main.user_dashboard'))

    context = {
        'form': form
    }
    return render('pages/login.html', **context)


@main.route('/user/dashboard', methods=["GET", "POST"])
@login_is_required
def user_dashboard(user):
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
    form = TargetForm()

    context = {
        'form': form
    }

    try:
        target = session_db.query(TargetValue).filter_by(
            user_id=user.id).first()
        if target:
            context['user_target'] = target.value if target else None
    except Exception:
        ...

    # If user submit the form:
    if request.method == "POST":
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
                return redirect(url_for('main.user_dashboard'))

            target.value = value
            session_db.commit()
            flash("valor atualizado com sucesso", "success")
            return redirect(url_for('main.user_dashboard'))
        else:
            flash("Valor inválido!", "error")

    try:
        currency = session_db.query(CurrencyValues).order_by(
            CurrencyValues.id.desc()
        ).first()
        if currency:
            last_update = currency.date if currency else None

            actual_date = datetime.datetime.now()
            if last_update is not None and actual_date is not None:
                sub = actual_date - last_update
                minutes = parse_time(f"{sub}")
            context['currency'] = currency.to_dict() if currency else None
            context['minutes'] = str(minutes).replace(
                '.0', '') if minutes else None
    except Exception:
        ...

    return render(
        'pages/dashboard.html', **context)


@main.route('/user/update', methods=["GET", "POST"])
@login_is_required
def user_update(user):
    form = UpdateUserForm(
        username=user.username,
        email=user.email
    )

    context = {
        "form": form
    }

    if request.method == "POST":
        if form.validate_on_submit():
            form_data = form.data
            user.username = form_data['username']
            user.email = form_data['email']
            session_db.commit()
            flash("Dados salvos com sucesso!", "success")
            return redirect('/user/update')
        else:
            flash("Erro no formulário", "error")

    return render("pages/user_update.html", **context)


@main.route('/user/change-password', methods=["GET", "POST"])
@login_is_required
def change_password(user):
    form = ChangePasswordForm()
    context = {"form": form}

    if request.method == "POST":
        if form.validate_on_submit():
            form_data = form.data
            user.set_password(form_data['new_password']) if user else None
            session_db.commit()
            flash("Senha atualizada com sucesso!", "success")
            return redirect('/user/update')
        else:
            flash("Erro no formulário", "error")

    return render("pages/change_password.html", **context)
