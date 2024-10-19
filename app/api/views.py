from flask import Blueprint, jsonify, request
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                current_user, jwt_required)
from flask_restful import Resource

from app.base.forms import TargetForm
from app.base.models import TargetValue, User, session_db

api_bp = Blueprint('api_views', __name__)


@api_bp.route('/api/register', methods=["POST"])
def api_register():
    data = request.json
    ...
    return jsonify()


@api_bp.route('/api/login', methods=["POST"])
def api_login():
    email = request.json.get('email', None) if request.json else None
    password = request.json.get('password', None) if request.json else None

    user = User.query.filter_by(email=email).one_or_none()

    if not user or not user.check_password(password):
        return jsonify("Wrong user or password"), 401

    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token
    })


@api_bp.route("/api/user", methods=["GET"])
@jwt_required()
def protected():
    # We can now access our sqlalchemy User object via `current_user`.
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'email': current_user.email
    })


class UserTargetAPI(Resource):
    @jwt_required()
    def get(self):
        target = TargetValue.query.filter_by(
            user_id=current_user.id).one_or_none()
        if not target:
            return jsonify({"error": "No target created by user"})
        return jsonify({"Target": target.value})

    @jwt_required()
    def post(self):
        existing_target = TargetValue.query.filter_by(
            user_id=current_user.id).one_or_none()
        if existing_target:
            return jsonify({"error": "this user already has a created target"})

        value = request.json.get('value') if request.json else None
        form = TargetForm(value=value)
        if form.validate_on_submit():
            new_target = TargetValue(
                value=value,
                user_id=current_user.id
            )
            session_db.add(new_target)
            session_db.commit()
            return jsonify(new_target.to_dict())
        else:
            return jsonify(form.errors)

    @jwt_required()
    def delete(self):
        target = TargetValue.query.filter_by(
            user_id=current_user.id).one_or_none()
        if not target:
            return jsonify({"message": "No target found"})
        session_db.delete(target)
        session_db.commit()
        return jsonify({"message": "Target deleted successful"})
