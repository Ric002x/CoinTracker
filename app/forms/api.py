import re
from collections import defaultdict

from flask_jwt_extended import current_user

from ..models import User, session_db


class TargetAPIForm:
    def __init__(self, data):
        self.data: dict = data
        self.form_errors = defaultdict(list)
        self.fields = ["value"]

    def validate(self):
        for key, value in self.data.items():
            if key not in self.fields:
                self.form_errors['field_not_exist'].append(
                    f"The {key} field does not match any field in form"
                )
        if not self.data.get('value'):
            self.form_errors['value'].append(
                "This field is required")
            return False

        if not isinstance(self.data.get('value'), (float, int)):
            self.form_errors['value'].append(
                "A numeric value is required")
            return False

        if self.data.get('value') < 0:  # type: ignore
            self.form_errors['value'].append(
                "The value has to be positive")
            return False

        return True


class UserFormAPI:
    def __init__(self, data):
        self.data: dict = data
        self.form_errors = defaultdict(list)
        self.fields = ['username', 'email', 'password', 'repeat_password']

    def post_validate(self):
        for key, value in self.data.items():
            if key not in self.fields:
                self.form_errors['field_not_exist'].append(
                    f"The {key} field does not match any field in form"
                )

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
        for key, value in self.data.items():
            if key not in self.fields[0:2]:
                self.form_errors['field_not_exist'].append(
                    f"The {key} field does not match any field in form"
                )
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
                email_regex, self.data.get('email')):  # type: ignore
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
                password_regex, self.data.get('password')):  # type: ignore
            self.form_errors['password'].append(
                "The password must contain at least one uppercase letter, "
                "one lowercase letter, and one number."
            )


class LoginFormAPI:
    def __init__(self, data):
        self.data: dict = data
        self.form_errors = defaultdict(list)
        self.fields = ["email", "password"]

    def validate(self):
        for key, value in self.data.items():
            if key not in self.fields:
                self.form_errors['field_not_exist'].append(
                    f"The {key} field does not match any field in form"
                )
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


class ChangePasswordFormAPI:
    def __init__(self, data):
        self.data: dict = data
        self.form_errors = defaultdict(list)
        self.fields = ["old_password", "new_password", "repeat_password"]

    def validate(self):
        for key, value in self.data.items():
            if key not in self.fields:
                self.form_errors['field_not_exist'].append(
                    f"The {key} field does not match any field in form"
                )

        fields = {
            'old_password': self.data.get('old_password'),
            'new_password': self.data.get('new_password'),
            'repeat_password': self.data.get('repeat_password'),
        }
        for key, value in fields.items():
            if not key or not value:
                self.form_errors[key].append(
                    "This field is required"
                )

        if self.form_errors:
            return False

        user = session_db.query(User).filter_by(id=current_user.id).first()
        if not user or not user.check_password(self.data.get('old_password')):
            self.form_errors['old_password'].append(
                "the password is wrong"
            )

        if self.data.get('new_password') != self.data.get('repeat_password'):
            self.form_errors['new_password'].append(
                "The new password need to match with the repeat_password"
            )

        self.validate_password()

        if self.form_errors:
            return False

        return True

    def validate_password(self):
        password_regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*[1-9]).{8,}$"
        if self.data.get('new_password') and not re.match(
                password_regex, self.data.get('new_password')):  # type: ignore
            self.form_errors['new_password'].append(
                "The password must contain at least one uppercase letter, "
                "one lowercase letter, and one number."
            )
