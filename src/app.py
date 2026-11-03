from flask import Flask, jsonify
from .config import Config
from .database import init_app
from .routes.auth import bp as auth_bp
from .routes.users import bp as users_bp
from .routes.accounts import bp as accounts_bp
from .routes.transactions import bp as transactions_bp


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    init_app(app)
    for bp in (auth_bp, users_bp, accounts_bp, transactions_bp):
        app.register_blueprint(bp, url_prefix="/api" + bp.url_prefix)

    @app.get("/api/health")
    def health():
        return jsonify(status="ok"), 200

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify(error="Not found"), 404

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify(error="Request too large"), 413

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
