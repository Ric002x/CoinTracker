from flask import Flask, render_template

from .config import Config
from .extension import api, db, jwt


def create_app():

    from .auth import auth_pb
    from .oauth.api import oauth_api_pb
    from .views.api import api_bp
    from .views.base import main

    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    api.init_app(app)
    jwt.init_app(app)

    # from flask_cors import CORS
    # CORS(app, origins=['http://127.0.0.1:5500'])

    app.register_blueprint(main)
    app.register_blueprint(auth_pb)
    app.register_blueprint(api_bp)
    app.register_blueprint(oauth_api_pb)

    # error templates

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('pages/errors/404.html'), 404

    return app
