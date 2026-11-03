from flask import Blueprint, g, jsonify
from ..database import get_db
from ..services.authentication import require_auth

bp = Blueprint("transactions", __name__, url_prefix="/transactions")


@bp.get("")
@require_auth()
def list_transactions():
    account_id = __import__("flask").request.args.get("account_id", type=int)
    db = get_db()
    if g.user["role"] == "ADMIN":
        if account_id:
            rows = db.execute(
                "SELECT t.id,t.account_id,t.description,t.amount_cents,t.created_at FROM transactions t WHERE t.account_id=? ORDER BY t.id DESC",
                (account_id,),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT t.id,t.account_id,t.description,t.amount_cents,t.created_at FROM transactions t ORDER BY t.id DESC"
            ).fetchall()
    else:
        if account_id:
            rows = db.execute(
                "SELECT t.id,t.account_id,t.description,t.amount_cents,t.created_at FROM transactions t JOIN accounts a ON a.id=t.account_id WHERE t.account_id=? AND a.user_id=? ORDER BY t.id DESC",
                (account_id, g.user["id"]),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT t.id,t.account_id,t.description,t.amount_cents,t.created_at FROM transactions t JOIN accounts a ON a.id=t.account_id WHERE a.user_id=? ORDER BY t.id DESC",
                (g.user["id"],),
            ).fetchall()
    return jsonify(transactions=[dict(row) for row in rows]), 200


@bp.get("/<int:transaction_id>")
@require_auth()
def get_transaction(transaction_id):
    db = get_db()
    if g.user["role"] == "ADMIN":
        row = db.execute(
            "SELECT t.id,t.account_id,t.description,t.amount_cents,t.created_at FROM transactions t WHERE t.id=?",
            (transaction_id,),
        ).fetchone()
    else:
        row = db.execute(
            "SELECT t.id,t.account_id,t.description,t.amount_cents,t.created_at FROM transactions t JOIN accounts a ON a.id=t.account_id WHERE t.id=? AND a.user_id=?",
            (transaction_id, g.user["id"]),
        ).fetchone()
    if row is None:
        return jsonify(error="Transaction not found"), 404
    return jsonify(transaction=dict(row)), 200
