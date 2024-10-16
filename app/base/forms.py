import re

from flask_wtf import FlaskForm
from wtforms import (EmailField, FloatField, PasswordField, StringField,
                     SubmitField)
from wtforms.validators import DataRequired, NumberRange, ValidationError

from .models import User, session_db


class AlertFormPOST(FlaskForm):
    value = FloatField('Valor em Reais (R$):', validators=[
        DataRequired(message="Submeta um valor para salva-lo"),
        NumberRange(min=0, message="O valor deve ser positivo")])
    submit = SubmitField("Enviar")


class RegisterForm(FlaskForm):
    username = StringField("Nome de Usuário:", validators=[
        DataRequired(message="Campo obrigatório"),
    ])
    email = EmailField("E-mail:", validators=[
        DataRequired(message="Campo obrigatório"),

    ])
    password = PasswordField("Senha:", validators=[
        DataRequired(message="Campo obrigatório"),
    ])
    repeat_password = PasswordField("Repita sua senha:", validators=[
        DataRequired(message="Campo obrigatório"),
    ])
    submit = SubmitField('Cadastrar')

    def validate_password(self, field):
        if self.password.data != self.repeat_password.data:
            raise ValidationError(
                "As senha não coincidem"
            )
        regex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*[1-9]).{8,}$')

        if not regex.match(str(field.data)):
            raise ValidationError(
                'A senha deve contar pelo menos 8 caracteres, '
                'incluindo letras maiúsculas e números')

    def validate_username(self, field):
        if len(field.data) < 4:
            raise ValidationError(
                "O nome de usuário precisa ter pelo menos 5 caracteres")

    def validate_email(self, field):
        existing_user = session_db.query(
            User).filter_by(email=field.data).first()
        if existing_user:
            raise ValidationError(
                "Já existe um usuário cadastrado com esse email")


class LoginForm(FlaskForm):
    email = EmailField("E-mail:", validators=[
        DataRequired(message="Campo obrigatório"),

    ])
    password = PasswordField("Senha", validators=[
        DataRequired(message="Campo obrigatório"),
    ])
    submit = SubmitField('Entrar')
