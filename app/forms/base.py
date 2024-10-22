import re

from flask import session
from flask_wtf import FlaskForm
from wtforms import (EmailField, FloatField, PasswordField, StringField,
                     SubmitField)
from wtforms.validators import DataRequired, NumberRange, ValidationError

from ..models import User, session_db


class TargetForm(FlaskForm):
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
        if self.data.get('password') != self.data.get('repeat_password'):
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


class UpdateUserForm(FlaskForm):
    username = StringField("Username:", validators=[
        DataRequired(message="Campo obrigatório")
    ])
    email = EmailField("E-mail:", validators=[
        DataRequired(message="Campo obrigatório"),
    ])

    def validate_username(self, field):
        if len(field.data) < 4:
            raise ValidationError(
                "O nome de usuário precisa ter pelo menos 5 caracteres")

    def validate_email(self, field):
        existing_user = session_db.query(
            User).filter_by(email=field.data).first()
        current_user = session_db.query(
            User).filter_by(id=session['user']).first()

        if existing_user and current_user:
            is_owner = existing_user.email == current_user.email

        if existing_user:
            if not is_owner:
                raise ValidationError(
                    "Já existe um usuário cadastrado com esse email")


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField("Senha atual:", validators=[
        DataRequired(message="Campo obrigatório"),
    ])
    new_password = PasswordField("Nova senha:", validators=[
        DataRequired(message="Campo obrigatório"),
    ])
    repeat_password = PasswordField("Repita sua nova senha:", validators=[
        DataRequired(message="Campo obrigatório"),
    ])

    def validate_old_password(self, field):
        user = session_db.query(User).filter_by(id=session['user']).first()

        check = user.check_password(field.data) if user else None
        if not user or check is False:
            raise ValidationError(
                "A senha inserida não coincide com a senha salva."
            )

    def validate_new_password(self, field):
        if self.data.get('new_password') != self.data.get('repeat_password'):
            raise ValidationError(
                "As senha não coincidem"
            )

        regex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*[1-9]).{8,}$')

        if not regex.match(str(field.data)):
            raise ValidationError(
                'A senha deve contar pelo menos 8 caracteres, '
                'incluindo letras maiúsculas e números')
