import datetime

from flask import Blueprint, flash, redirect
from flask_wtf import FlaskForm
from wtforms import FloatField, SubmitField
from wtforms.validators import DataRequired

from .auth import get_user, render, render_restricted, user_alredy_logged
from .models import CurrencyValues, TargetValue, session_db

main = Blueprint('main', __name__)


class AlertFormPOST(FlaskForm):
    value = FloatField('Valor em Reais (R$):', validators=[DataRequired()])
    submit = SubmitField("Enviar")


@main.route('/')
def home():
    return render('pages/home.html')


@main.route('/login')
@user_alredy_logged
def login_page():
    return render('pages/login.html')


def parse_time(time_str):
    hours, minutes, seconds = map(float, time_str.split(':'))
    return minutes


@main.route('/dashboard', methods=["GET", "POST"])
def user_dashboard():
    form = AlertFormPOST()
    if form.validate_on_submit():
        value = form.value.data
        user = get_user()
        target = session_db.query(TargetValue).filter_by(
            user_id=user.id).first()

        if not target:
            target = TargetValue(
                value=value,
                user_id=user.id
            )
            session_db.add(target)
            session_db.commit()
            flash("Valor enviado", "success")
            return redirect('/dashboard')

        target.value = value
        session_db.commit()
        flash("valor atualizado com sucesso", "success")
        return redirect('/dashboard')
    currency = session_db.query(CurrencyValues).order_by(
        CurrencyValues.id.desc()
    ).first()
    data_atual = datetime.datetime.now()
    data = currency.date  # type:ignore
    sub = data_atual - data
    minutes = parse_time(f"{sub}")
    context = {
        'currency': currency.to_dict() if currency else None,
        'minutes': str(minutes).replace('.0', ''),
        'form': form
    }
    return render_restricted(
        'pages/dashboard.html', **context)
