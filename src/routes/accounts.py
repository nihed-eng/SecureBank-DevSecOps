from flask import Blueprint, g, jsonify, request
from ..database import get_db
from ..services.authentication import require_auth

bp = Blueprint("accounts", __name__, url_prefix="/accounts")


@bp.post("")
@require_auth()
def create_account():
    data = request.get_json(silent=True) or {}
    label = data.get("label", "Main account")
    if not isinstance(label, str) or not label.strip() or len(label) > 80:
        return jsonify(error="label must be 1-80 characters"), 400
    db = get_db()
    cursor = db.execute(
        "INSERT INTO accounts(user_id,label) VALUES (?,?)",
        (g.user["id"], label.strip()),
    )
    db.commit()
    row = db.execute(
        "SELECT id,user_id,label,balance_cents,created_at FROM accounts WHERE id=?",
        (cursor.lastrowid,),
    ).fetchone()
    return jsonify(account=dict(row)), 201


@bp.get("")
@require_auth()
def list_accounts():
    db = get_db()
    if g.user["role"] == "ADMIN":
        rows = db.execute(
            "SELECT id,user_id,label,balance_cents,created_at FROM accounts ORDER BY id"
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT id,user_id,label,balance_cents,created_at FROM accounts WHERE user_id=? ORDER BY id",
            (g.user["id"],),
        ).fetchall()
    return jsonify(accounts=[dict(row) for row in rows]), 200


@bp.get("/<int:account_id>")
@require_auth()
def get_account(account_id):
    db = get_db()
    # The demo vulnerability deliberately omits the ownership predicate.
    if db_demo := __import__("flask").current_app.config["VULNERABLE_DEMO"]:
        row = db.execute(
            "SELECT id,user_id,label,balance_cents,created_at FROM accounts WHERE id=?",
            (account_id,),
        ).fetchone()
    elif g.user["role"] == "ADMIN":
        row = db.execute(
            "SELECT id,user_id,label,balance_cents,created_at FROM accounts WHERE id=?",
            (account_id,),
        ).fetchone()
    else:
        row = db.execute(
            "SELECT id,user_id,label,balance_cents,created_at FROM accounts WHERE id=? AND user_id=?",
            (account_id, g.user["id"]),
        ).fetchone()
    if row is None:
        return jsonify(error="Account not found"), 404
    return jsonify(account=dict(row)), 200
