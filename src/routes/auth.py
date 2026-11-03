import re
from flask import Blueprint, jsonify, request
from ..database import get_db
from ..services.authentication import hash_password, verify_password, issue_token

bp = Blueprint("auth", __name__, url_prefix="/auth")


def _body():
    return request.get_json(silent=True) or {}


@bp.post("/register")
def register():
    data = _body()
    username, email, password = (
        data.get("username"),
        data.get("email"),
        data.get("password"),
    )

    if not all(isinstance(v, str) for v in (username, email, password)):
        return jsonify(error="username, email and password are required"), 400

    username, email = username.strip(), email.strip().lower()

    if (
        not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", username)
        or len(email) > 254
        or "@" not in email
    ):
        return jsonify(error="Invalid username or email"), 400

    if len(password) < 12 or len(password) > 128:
        return jsonify(error="Password must be 12-128 characters"), 400

    db = get_db()

    try:
        cursor = db.execute(
            "INSERT INTO users(username,email,password_hash) VALUES (?,?,?)",
            (username, email, hash_password(password)),
        )

        user = db.execute(
            "SELECT id,username,email,role FROM users WHERE id=?",
            (cursor.lastrowid,),
        ).fetchone()

        db.commit()

    except Exception:
        db.rollback()
        return jsonify(error="Username or email already exists"), 409

    return jsonify(user=dict(user), token=issue_token(user)), 201


@bp.post("/login")
def login():
    data = _body()
    username, password = data.get("username"), data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="username and password are required"), 400

    db = get_db()

    row = db.execute(
        "SELECT * FROM users WHERE username=?",
        (username,),
    ).fetchone()

    if row is None or not verify_password(password, row["password_hash"]):
        return jsonify(error="Invalid credentials"), 401

    return (
        jsonify(
            user={
                "id": row["id"],
                "username": row["username"],
                "email": row["email"],
                "role": row["role"],
            },
            token=issue_token(row),
        ),
        200,
    )
