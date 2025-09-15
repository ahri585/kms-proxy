# app.py
from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from config import Config

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)

    # 블루프린트 등록
    from routes_crypto import crypto_bp
    app.register_blueprint(crypto_bp)

    # 헬스체크 (JSON + name 포함)
    @app.get("/api/health")
    def health():
        return jsonify({
            "ok": True,
            "name": "Lockument Demo Portal",
        }), 200

    return app

app = create_app()

