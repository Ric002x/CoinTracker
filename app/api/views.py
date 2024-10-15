from flask import request, session
from flask_restful import Resource

from app.base.models import TargetValue, session_db

from .auth import token_is_required


class Alerts(Resource):
    # @token_is_required
    # def get(self):  # Crete "User Dashboar"
    #     return {"Success": "This request was succesful"}

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
