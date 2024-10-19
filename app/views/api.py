from flask import Blueprint, jsonify, request
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                current_user, get_jwt_identity, jwt_required)
from flask_restful import Resource

from ..forms import LoginFormAPI, RegisterAPIForm, TargetAPIForm
from ..models import TargetValue, User, session_db

api_bp = Blueprint('api', __name__)


@api_bp.route('/api/register', methods=["POST"])
def api_user_register():
    data = request.json
    form = RegisterAPIForm(data)

    if form.validate():
        form_data = form.data
        if form_data:
            new_user = User(
                username=form_data['username'],
                email=form_data['email'],
                password=None,
                google_id=None
            )
            new_user.set_password(form_data['password'])
            session_db.add(new_user)
            session_db.commit()
            return jsonify(new_user.to_dict()), 201

    return jsonify(form.form_errors), 400


@api_bp.route('/api/create_token', methods=["POST"])
def api_create_token():
    data = request.json
    form = LoginFormAPI(data)

    if form.validate():
        form_data = form.data
        if form_data:
            user = User.query.filter_by(email=form_data['email']).one_or_none()

            if not user or not user.check_password(form_data['password']):
                return jsonify("Wrong user or password"), 401

            access_token = create_access_token(user)
            refresh_token = create_refresh_token(user)
            return jsonify({
                'access_token': access_token,
                'refresh_token': refresh_token
            }), 200
    return jsonify(form.form_errors), 400


@api_bp.route('/api/refresh_token', methods=["POST"])
@jwt_required(refresh=True)
def api_refresh_token():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify(access_token=access_token), 200


@api_bp.route("/api/user", methods=["GET"])
@jwt_required()
def protected():
    # We can now access our sqlalchemy User object via `current_user`.
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'email': current_user.email
    }), 200


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
        form = TargetAPIForm(value=value)
        if form.validate():
            new_target = TargetValue(
                value=value,
                user_id=current_user.id
            )
            session_db.add(new_target)
            session_db.commit()
            return jsonify(new_target.to_dict())
        else:
            return jsonify(form.form_errors)

    @jwt_required()
    def delete(self):
        target = TargetValue.query.filter_by(
            user_id=current_user.id).one_or_none()
        if not target:
            return jsonify({"message": "No target found"})
        session_db.delete(target)
        session_db.commit()
        return jsonify({"message": "Target deleted successful"})


api_bp.add_url_rule(
    '/api/target/', view_func=UserTargetAPI.as_view('user_target_api'))
