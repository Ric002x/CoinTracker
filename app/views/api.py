from flask import Blueprint, jsonify, request
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                current_user, get_jwt_identity, jwt_required)
from flask_restful import Resource

from ..forms.api import (ChangePasswordFormAPI, LoginFormAPI, TargetAPIForm,
                         UserFormAPI)
from ..models import CurrencyValues, TargetValue, User, session_db

api_bp = Blueprint('api', __name__)


@api_bp.route('/api/create_token', methods=["POST"])
def api_create_token():
    data = request.json
    form = LoginFormAPI(data)

    if form.validate():
        user = User.query.filter_by(email=form.data['email']).one_or_none()

        if not user or not user.check_password(form.data['password']):
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
        user = session_db.query(User).filter_by(
            id=current_user.id).first() or None
        return jsonify(user.to_dict()), 200  # type: ignore

    def post(self):
        data = request.json
        form = UserFormAPI(data)

        if form.post_validate():
            new_user = User(
                username=form.data['username'],
                email=form.data['email'],
                password=None,
                google_id=None
            )
            new_user.set_password(form.data['password'])
            session_db.add(new_user)
            session_db.commit()
            return jsonify(new_user.to_dict()), 201

        return jsonify(form.form_errors), 400

    @jwt_required()
    def patch(self):
        data = request.json
        form = UserFormAPI(data)

        if form.patch_validate():
            user = User.query.filter_by(
                email=current_user.email).one_or_none()
            if 'username' in form.data:
                user.username = form.data['username']  # type: ignore
            if 'email' in form.data:
                user.email = form.data['email']  # type: ignore
            session_db.commit()
            return jsonify(user.to_dict()), 200  # type: ignore

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

    user = session_db.query(User).filter_by(id=current_user.id).first()
    user.set_password(form.data['new_password'])  # type: ignore
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
        return jsonify(target.to_dict()), 200

    @jwt_required()
    def post(self):
        data = request.json
        form = TargetAPIForm(data)

        if form.validate():
            try:
                new_target = TargetValue(
                    value=form.data['value'],
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
            existing_target.value = form.data['value']
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


@api_bp.route('/api/currency/list', methods=['GET'])
def currency_get_list():
    currency = CurrencyValues.list_all()
    if not currency:
        return jsonify({"msg": "A value was not found"}), 500
    return jsonify(currency)


@api_bp.route('/api/currency/latest', methods=["GET"])
def currency_get_object():
    currency = session_db.query(CurrencyValues).order_by(
        CurrencyValues.id.desc()
    ).first()
    if not currency:
        return jsonify({"msg": "A value was not found"}), 500
    return jsonify(currency.to_dict())
