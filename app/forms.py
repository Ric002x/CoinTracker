import re
from collections import defaultdict

from flask_jwt_extended import current_user
from flask_wtf import FlaskForm
from wtforms import (EmailField, FloatField, PasswordField, StringField,
                     SubmitField)
from wtforms.validators import DataRequired, NumberRange, ValidationError

from .models import User, session_db


class TargetForm(FlaskForm):
    value = FloatField('Valor em Reais (R$):', validators=[
        DataRequired(message="Submeta um valor para salva-lo"),
        NumberRange(min=0, message="O valor deve ser positivo")])
    submit = SubmitField("Enviar")


class TargetAPIForm:
    def __init__(self, value):
        self.value = value
        self.form_errors = defaultdict(list)

    def validate(self):
        if not self.value:
            self.form_errors['value'].append(
                "This field is required")
            return False

        if not isinstance(self.value, (float, int)):
            self.form_errors['value'].append(
                "A numeric value is required")
            return False

        if self.value < 0:
            self.form_errors['value'].append(
                "The value has to be positive")
            return False


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


class UserFormAPI:
    def __init__(self, data):
        self.data = data
        self.form_errors = defaultdict(list)

    def post_validate(self):
        if not isinstance(self.data, dict):
            self.form_errors["msg"].append("A dict object must be used")
            return False
        fields = {
            'email': self.data.get('email'),
            'username': self.data.get('username'),
            'password': self.data.get('password'),
            'repeat_password': self.data.get('repeat_password')
        }
        for key, value in fields.items():
            if not key or not value:
                self.form_errors[key].append(
                    "This field is required"
                )
        if self.form_errors:
            return False

        self.validate_email()
        self.validate_username()
        self.validate_password()

        if self.data.get('password') != self.data.get('repeat_password'):
            self.form_errors['password'].append(
                "The passwords need to match"
            )

        if self.form_errors:
            return False

        return True

    def patch_validate(self):
        if not isinstance(self.data, dict):
            self.form_errors["msg"].append("A dict object must be used")
            return False

        if self.data.get('username'):
            self.validate_username()
        if self.data.get('email'):
            self.validate_email(method='patch')

        if self.form_errors:
            return False

        return True

    def validate_email(self, method="post"):
        email_regex = r"^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?\
        ^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0\
        -9-]*[a-z0-9])?$"
        if self.data.get('email') and not re.match(
                email_regex, self.data.get('email')):
            self.form_errors['email'].append(
                "Invalid email format"
            )

        existing_user = User.query.filter_by(
            email=self.data.get('email')).one_or_none()

        if method == 'post':
            if existing_user and existing_user.email == self.data.get('email'):
                self.form_errors['email'].append(
                    "A user with that email already exist"
                )
        elif method == 'patch':
            if existing_user:
                user_is_owner = existing_user.email == current_user.email

                if not user_is_owner:
                    self.form_errors['email'].append(
                        "A user with that email already exist"
                    )

    def validate_username(self):
        username_regex = r"^[A-Z][A-Za-z0-9-_]{4,}$"
        if self.data.get('username') and not re.match(
                username_regex, self.data['username']):
            self.form_errors['username'].append(
                "The username must have at least 5 characters, and contain "
                "at least one uppercase letter. You can only "
                "use letters, numbers, hyphens (-), and underscores (_)"
            )

    def validate_password(self):
        password_regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*[1-9]).{8,}$"
        if self.data.get('password') and not re.match(
                password_regex, self.data.get('password')):
            self.form_errors['password'].append(
                "The password must contain at least one uppercase letter, "
                "one lowercase letter, and one number."
            )


class LoginForm(FlaskForm):
    email = EmailField("E-mail:", validators=[
        DataRequired(message="Campo obrigatório"),

    ])
    password = PasswordField("Senha", validators=[
        DataRequired(message="Campo obrigatório"),
    ])
    submit = SubmitField('Entrar')


class LoginFormAPI:
    def __init__(self, data):
        self.data = data
        self.form_errors = defaultdict(list)

    def validate(self):
        if not isinstance(self.data, dict):
            self.form_errors["msg"].append("A dict object must be used")
            return False
        fields = {
            'email': self.data.get('email'),
            'password': self.data.get('password')
        }
        for key, value in fields.items():
            if not key or not value:
                self.form_errors[key].append(
                    "This field is required"
                )
        if self.form_errors:
            return False

        return True
