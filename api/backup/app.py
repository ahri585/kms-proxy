from flask import Flask, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from config import Config

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)

    # --- 블루프린트 등록 (API만 담당) ---
    from routes_crypto import crypto_bp
    from routes_auth import auth_bp
    app.register_blueprint(crypto_bp)   # /api/encrypt, /api/decrypt 등
    app.register_blueprint(auth_bp)     # /api/login, /api/register 등

    # --- 화면 라우트 (템플릿 렌더링 전용) ---
    @app.get("/")
    def index_page():
        # 기본 화면은 업로드 페이지
        return render_template("upload.html")

    @app.get("/login")
    def login_page():
        return render_template("login.html")

    @app.get("/register")
    def register_page():
        return render_template("register.html")

    @app.get("/upload")
    def upload_page():
        return render_template("upload.html")

    # --- 헬스체크 ---
    @app.get("/api/health")
    def health():
        return jsonify({
            "ok": True,
            "name": "Lockument Demo Portal",
        }), 200

    return app

app = create_app()

