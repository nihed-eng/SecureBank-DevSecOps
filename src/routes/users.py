from flask import Blueprint, current_app, g, jsonify, request
from ..database import get_db
from ..services.authentication import require_auth

bp = Blueprint("users", __name__, url_prefix="/users")

@bp.get("/me")
@require_auth()
def me():
    return jsonify(user=dict(g.user)), 200

@bp.get("/<int:user_id>")
@require_auth()
def user_detail(user_id):
    if g.user["role"] != "ADMIN" and g.user["id"] != user_id:
        return jsonify(error="Forbidden"), 403
    row = get_db().execute("SELECT id,username,email,role,created_at FROM users WHERE id=?", (user_id,)).fetchone()
    if row is None:
        return jsonify(error="User not found"), 404
    return jsonify(user=dict(row)), 200

@bp.get("/demo-profile")
def demo_profile():
    # The response is JSON, not HTML. In demo mode this intentionally emits attacker-controlled markup
    # so that a client which renders it unsafely illustrates an XSS source/sink.
    value = request.args.get("name", "visitor")
    if current_app.config["VULNERABLE_DEMO"]:
        return f"<h1>Profile: {value}</h1>", 200, {"Content-Type": "text/html; charset=utf-8"}
    return jsonify(profile={"name": value}), 200
