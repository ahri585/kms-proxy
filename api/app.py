import os, base64, json
from flask import Flask, jsonify, request, render_template
import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from secrets import token_bytes


REGION = os.getenv("AWS_REGION", "ap-northeast-2")
KMS_KEY_ID = os.getenv("KMS_KEY_ID", "alias/KEK")


app = Flask(__name__)
kms = boto3.client("kms", region_name=REGION)


@app.get("/api/health")
def health():
    return "api ok\n", 200

@app.get("/api/kms-test")
def kms_test():
    try:
        res = kms.generate_data_key(KeyId=KMS_KEY_ID, KeySpec="AES_256")

        ct_len = len(res.get("CiphertextBlob", b"") or b"")
        return jsonify({"ok": True, "ciphertext_blob_len": ct_len}), 200
    except ClientError as e:
        return jsonify({"ok":False, "error": str(e)}), 500

@app.post("/api/encrypt")
def encrypt():
    try:
        body = request.get_json(force=True, silent=True) or {}
        if "data" not in body:
            return jsonify({"ok": False, "error": "missing 'data'"}), 400

        raw = body["data"]
        if not isinstance(raw, str):
            return jsonify({"ok": False, "error": "data must be string"}), 400
        plaintext = raw.encode("utf-8")

        aad = body.get("aad")
        aad_bytes = aad.encode("utf-8") if isinstance(aad, str) else None

        # 1) KMS에서 DEK 생성 (Plaintext + WDEK)
        resp = kms.generate_data_key(KeyId=KMS_KEY_ID, KeySpec="AES_256")
        dek_plain = resp["Plaintext"]          # bytes
        wdek = resp["CiphertextBlob"]          # bytes (wrapped DEK)

        # 2) AES-GCM 암호화
        iv = token_bytes(12)                   # 96-bit nonce
        aesgcm = AESGCM(dek_plain)
        ciphertext = aesgcm.encrypt(iv, plaintext, aad_bytes)  # returns ct||tag

        # 3) Base64 인코딩 후 반환
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

        # 1) KMS로 WDEK 복호화 → 평문 DEK 얻기
        resp = kms.decrypt(CiphertextBlob=wdek, KeyId=KMS_KEY_ID)
        dek_plain = resp["Plaintext"]

        # 2) AES-GCM 복호화
        aesgcm = AESGCM(dek_plain)
        plaintext = aesgcm.decrypt(iv, ciphertext, aad_bytes)

        return jsonify({"ok": True, "plaintext": plaintext.decode("utf-8")}), 200

    except ClientError as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    except Exception as e:
        return jsonify({"ok": False, "error": f"decrypt-failed: {e}"}), 500

@app.get("/")
def home():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
