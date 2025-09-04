import os, base64, json
from flask import Flask, jsonify, request, render_template
import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from secrets import token_bytes
from flask_sqlalchemy import SQLAlchemy
from config import Config
from sqlalchemy import text

REGION = os.getenv("AWS_REGION", "ap-northeast-2")
KMS_KEY_ID = os.getenv("KMS_KEY_ID", "alias/KEK")

db = SQLAlchemy()

app = Flask(__name__)
app.config.from_object(Config)

# DATABASE_URL 없으면 바로 명확히 실패시켜서 원인 찾기 쉽게
if not app.config.get("SQLALCHEMY_DATABASE_URI"):
    raise RuntimeError("DATABASE_URL not set")

db.init_app(app)

# boto3 클라이언트는 여기서 생성
kms = boto3.client("kms", region_name=REGION)

# --- 헬스체크: nginx/gunicorn 확인용 ---
@app.get("/api/health")
def health():
    return "api ok\n", 200

# --- DB 핑 (선택: 연결 확인용) ---
@app.get("/api/dbping")
def dbping():
    with db.engine.connect() as conn:
        row = conn.execute(text("select current_database(), current_user, now()")).fetchone()
        return {"db": row[0], "user": row[1], "now": str(row[2])}, 200

# --- KMS 테스트 ---
@app.get("/api/kms-test")
def kms_test():
    try:
        res = kms.generate_data_key(KeyId=KMS_KEY_ID, KeySpec="AES_256")
        ct_len = len(res.get("CiphertextBlob", b"") or b"")
        return jsonify({"ok": True, "ciphertext_blob_len": ct_len}), 200
    except ClientError as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# --- 암/복호화 ---
@app.post("/api/encrypt")
def encrypt():
    try:
        body = request.get_json(force=True, silent=True) or {}
        if "data" not in body:
            return jsonify({"ok": False, "error": "missing 'data'"}), 400

        plaintext = body["data"].encode("utf-8") if isinstance(body["data"], str) else None
        if plaintext is None:
            return jsonify({"ok": False, "error": "data must be string"}), 400

        aad = body.get("aad")
        aad_bytes = aad.encode("utf-8") if isinstance(aad, str) else None

        resp = kms.generate_data_key(KeyId=KMS_KEY_ID, KeySpec="AES_256")
        dek_plain = resp["Plaintext"]
        wdek = resp["CiphertextBlob"]

        iv = token_bytes(12)
        aesgcm = AESGCM(dek_plain)
        ciphertext = aesgcm.encrypt(iv, plaintext, aad_bytes)

        out = {
            "ok": True,
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "iv": base64.b64encode(iv).decode(),
            "wdek": base64.b64encode(wdek).decode()
        }
        if aad is not None:
            out["aad"] = aad
        return jsonify(out), 200
    except ClientError as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    except Exception as e:
        return jsonify({"ok": False, "error": f"encrypt-failed: {e}"}), 500

@app.post("/api/decrypt")
def decrypt():
    try:
        body = request.get_json(force=True, silent=True) or {}
        for k in ("ciphertext", "iv", "wdek"):
            if k not in body:
                return jsonify({"ok": False, "error": f"missing '{k}'"}), 400

        ciphertext = base64.b64decode(body["ciphertext"])
        iv = base64.b64decode(body["iv"])
        wdek = base64.b64decode(body["wdek"])
        aad = body.get("aad")
        aad_bytes = aad.encode("utf-8") if isinstance(aad, str) else None

        resp = kms.decrypt(CiphertextBlob=wdek)  # KeyId 생략 권장(토큰에 키정보 포함)
        dek_plain = resp["Plaintext"]

        aesgcm = AESGCM(dek_plain)
        plaintext = aesgcm.decrypt(iv, ciphertext, aad_bytes)

        return jsonify({"ok": True, "plaintext": plaintext.decode("utf-8")}), 200
    except ClientError as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    except Exception as e:
        return jsonify({"ok": False, "error": f"decrypt-failed: {e}"}), 500

# --- 루트 라우트 하나만 유지 ---
@app.get("/")
def index():
    return "Flask + Postgres 연결 성공", 200

