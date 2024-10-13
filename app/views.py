from auth import token_is_required
from flask import request, session
from flask_restful import Resource
from models import TargetValue, session_db


class Alerts(Resource):
    @token_is_required
    def post(self):
        data = request.json

        target_value = session_db.query(TargetValue).filter_by(
            user_id=session['user']).first()
        if not target_value:
            value = data['value']  # type: ignore
            try:
                target_value = TargetValue(
                    value=value,
                    user_id=session['user']
                )
                session_db.add(target_value)
                session_db.commit()
                return {"Target criado": f"{value}"}
            except Exception as e:
                return {"Erro": f"Não foi possível criar seu target: {e}"}
