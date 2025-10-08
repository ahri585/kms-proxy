import os, re, time, jwt
from functools import wraps
from datetime import datetime
from flask import Blueprint, request, jsonify, render_template, g
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError

from app import db
from models import User

auth_bp = Blueprint("auth", __name__, url_prefix="/api")

# ─────────────────────────────────────────────────────────────
# 환경설정
# ─────────────────────────────────────────────────────────────
JWT_SECRET = os.getenv("JWT_SECRET", "change_this_in_prod_please")
JWT_EXPIRES = int(os.getenv("JWT_ACCESS_EXPIRES", "600"))  # 10분(초)
JWT_ALG = "HS256"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# ─────────────────────────────────────────────────────────────
# 유틸
# ─────────────────────────────────────────────────────────────
def _make_token(user_id: int) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user_id),   # 🔥 반드시 문자열로 저장
        "iat": now,
        "exp": now + JWT_EXPIRES,
        "iss": "lockument-api",
        "typ": "access",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def _decode_token(token: str):
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])

def jwt_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"ok": False, "error": "missing_bearer"}), 401
        token = auth.split(" ", 1)[1].strip()
        try:
            payload = _decode_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"ok": False, "error": "token_expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"ok": False, "error": "invalid_token"}), 401
        # 🔥 다시 int 변환
        g.user_id = int(payload.get("sub"))

        return fn(*args, **kwargs)
    return wrapper

def _ok(data=None, **extra):
    body = {"ok": True}
    if data: body.update(data)
    if extra: body.update(extra)
    return jsonify(body)

def _bad(err, status=400, **extra):
    body = {"ok": False, "error": err}
    if extra: body.update(extra)
    return jsonify(body), status

# ─────────────────────────────────────────────────────────────
# 회원가입
# ─────────────────────────────────────────────────────────────
@auth_bp.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    username = (data.get("username") or "").strip() or None
    password = data.get("password") or ""

    if not EMAIL_RE.match(email):
        return _bad("invalid_email")
    if len(password) < 8:
        return _bad("weak_password", msg="password must be >= 8 chars")

    # 중복 체크 + 저장
    try:
        user = User(email=email, username=username,
                    password_hash=generate_password_hash(password),

                    created_at=datetime.utcnow())
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return _bad("email_taken", status=409)

    token = _make_token(user.id)
    return _ok({"user": user.to_dict(), "access_token": token, "expires_in": JWT_EXPIRES})

# ─────────────────────────────────────────────────────────────
# 로그인
# ─────────────────────────────────────────────────────────────
@auth_bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return _bad("invalid_credentials", status=401)

    token = _make_token(user.id)
    return _ok({"user": user.to_dict(), "access_token": token, "expires_in": JWT_EXPIRES})

# ─────────────────────────────────────────────────────────────
# 내 정보
# ─────────────────────────────────────────────────────────────
@auth_bp.get("/me")
@jwt_required
def me():
    user = User.query.get(g.user_id)
    if not user:
        return _bad("user_not_found", status=404)
    return _ok({"user": user.to_dict()})

# ─────────────────────────────────────────────────────────────
# 비밀번호 변경 (옵션)
# ─────────────────────────────────────────────────────────────
@auth_bp.post("/change_password")
@jwt_required
def change_password():
    data = request.get_json(silent=True) or {}
    old_pw = data.get("old_password") or ""
    new_pw = data.get("new_password") or ""
    if len(new_pw) < 8:
        return _bad("weak_password", msg="new password must be >= 8 chars")

    user = User.query.get(request.user_id)
    if not user or not check_password_hash(user.password_hash, old_pw):
        return _bad("invalid_credentials", status=401)

    user.password_hash = generate_password_hash(new_pw)
    db.session.commit()
    return _ok({"msg": "password_changed"})

def get_current_user():
    """jwt_required가 인증한 사용자 객체 반환"""
    user_id = g.user_id  # 또는 jwt에서 복원
    return User.query.get(user_id)

