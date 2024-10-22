from flask import Blueprint, jsonify, request
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                current_user, get_jwt_identity, jwt_required)
from flask_restful import Resource

from ..forms.api import (ChangePasswordFormAPI, LoginFormAPI, TargetAPIForm,
                         UserFormAPI)
from ..models import TargetValue, User, session_db

api_bp = Blueprint('api', __name__)


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

            access_token = create_access_token(user.id)
            refresh_token = create_refresh_token(user.id)
            tokens = {
                'refresh_token': refresh_token,
                'access_token': access_token
            }
            return jsonify(tokens)
    return jsonify(form.form_errors), 400


@api_bp.route('/api/refresh_token', methods=["POST"])
@jwt_required(refresh=True)
def api_refresh_token():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify(access_token=access_token), 200


class UserAPI(Resource):
    @jwt_required()
    def get(self):
        user = User.query.filter_by(id=current_user.id).one_or_none()
        if user:
            return jsonify(user.to_dict()), 200
        return jsonify({
            "msg": "Not a logged user"
        }), 400

    def post(self):
        data = request.json
        form = UserFormAPI(data)

        if form.post_validate():
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

    @jwt_required()
    def patch(self):
        data = request.json
        form = UserFormAPI(data)

        if form.patch_validate():
            form_data = form.data
            user = User.query.filter_by(
                email=current_user.email).one_or_none()
            if user and form_data:
                if 'username' in form_data:
                    user.username = form_data['username']
                if 'email' in form_data:
                    user.email = form_data['email']
                session_db.commit()
                return jsonify(user.to_dict()), 200

        return jsonify(form.form_errors), 400


api_bp.add_url_rule(
    '/api/user/', view_func=UserAPI.as_view('user_api'))


@api_bp.route('/api/user/change-password', methods=["patch"])
@jwt_required()
def change_password():
    data = request.json
    form = ChangePasswordFormAPI(data)

    if not form.validate():
        return jsonify(form.form_errors), 400

    form_data = form.data
    user = session_db.query(User).filter_by(id=current_user.id).first()
    if not user:
        return jsonify({
            "msg": "user not found"
        }), 400
    user.set_password(form_data['new_password'])
    session_db.commit()
    return jsonify({
        "msg": "Password updated successfully"
    }), 200


class UserTargetAPI(Resource):
    @jwt_required()
    def get(self):
        target = TargetValue.query.filter_by(
            user_id=current_user.id).one_or_none()
        if not target:
            return jsonify({"error": "No target created by user"}), 400
        return jsonify({"Target": target.value}), 200

    @jwt_required()
    def post(self):
        data = request.json
        form = TargetAPIForm(data)

        if form.validate():
            form_data = form.data
            if form_data:
                try:
                    new_target = TargetValue(
                        value=form_data['value'],
                        user_id=current_user.id
                    )
                    session_db.add(new_target)
                    session_db.commit()
                except Exception:
                    return jsonify({
                        "msg": "failed to create. this user already has a "
                        "created target"
                    }), 400
                return jsonify(new_target.to_dict()), 201
        else:
            return jsonify(form.form_errors), 400

    @jwt_required()
    def patch(self):
        data = request.json
        form = TargetAPIForm(data)
        existing_target = TargetValue.query.filter_by(
            user_id=current_user.id).one_or_none()

        if not existing_target:
            return jsonify({
                "msg": "no target to update. plase, create one first"
            }), 400

        if form.validate():
            form_data = form.data
            if form_data:
                existing_target.value = form_data['value']
                session_db.commit()
                return jsonify(existing_target.to_dict()), 200
        return jsonify(form.form_errors), 400

    @jwt_required()
    def delete(self):
        target = TargetValue.query.filter_by(
            user_id=current_user.id).one_or_none()
        if not target:
            return jsonify({"message": "No target found"}), 400
        session_db.delete(target)
        session_db.commit()
        return jsonify({"message": "Target deleted successful"}), 200


api_bp.add_url_rule(
    '/api/target/', view_func=UserTargetAPI.as_view('user_target_api'))
