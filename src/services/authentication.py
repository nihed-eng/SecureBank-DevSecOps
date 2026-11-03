from functools import wraps
from flask import current_app, g, jsonify, request
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import check_password_hash, generate_password_hash


def hash_password(password):
    # Deliberately weak hashing is isolated to the local training mode.
    if current_app.config["VULNERABLE_DEMO"]:
        import hashlib
        return "demo-sha256$" + hashlib.sha256(password.encode()).hexdigest()
    return generate_password_hash(password, method="scrypt")

def verify_password(password, stored):
    if stored.startswith("demo-sha256$"):
        import hashlib
        return stored == "demo-sha256$" + hashlib.sha256(password.encode()).hexdigest()
    return check_password_hash(stored, password)

def _serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="securebank-auth")

def issue_token(user):
    return _serializer().dumps({"sub": user["id"], "role": user["role"]})

def current_user():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    try:
        data = _serializer().loads(header[7:], max_age=3600)
    except (BadSignature, SignatureExpired):
        return None
    from ..database import get_db
    return get_db().execute("SELECT id, username, email, role FROM users WHERE id=?", (data.get("sub"),)).fetchone()

def require_auth(admin=False):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                return jsonify(error="Authentication required"), 401
            if admin and user["role"] != "ADMIN":
                return jsonify(error="Administrator role required"), 403
            g.user = user
            return fn(*args, **kwargs)
        return wrapped
    return decorator
