import base64, json, boto3,os
from typing import Tuple, Dict, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from secrets import token_bytes
from flask import current_app

# ──────────────────────────────
# 환경설정
# ──────────────────────────────
REGION = os.getenv("AWS_REGION", "ap-northeast-2")
KMS_KEY_ID = os.getenv("KMS_KEY_ID")  
kms = boto3.client("kms", region_name=REGION)
# ──────────────────────────────
# 암호화 (Encryption)
# ──────────────────────────────
def encrypt_bytes(data: bytes, meta: Optional[Dict] = None) -> Dict:
    """
    주어진 데이터 바이트(data)를 KMS DataKey + AES-GCM으로 암호화.
    반환: DB 저장용 dict (token, wdek, iv, ciphertext, tag, meta)
    """
    try:
        # 1️⃣ 데이터키 생성
        resp = kms.generate_data_key(KeyId=KMS_KEY_ID, KeySpec="AES_256")
        dek_plain = resp["Plaintext"]
        wdek = resp["CiphertextBlob"]

        # 2️⃣ AES-GCM 암호화
        iv = token_bytes(12)
        aesgcm = AESGCM(dek_plain)
        ciphertext = aesgcm.encrypt(iv, data, None)

        # 3️⃣ 결과 포장 (base64 인코딩)
        return {
            "wdek": base64.b64encode(wdek).decode(),
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "tag": "",
            "meta": json.dumps(meta or {}, ensure_ascii=False)
        }

    except Exception as e:
        current_app.logger.exception("encrypt_bytes_failed")
        raise


# ──────────────────────────────
# 복호화 (Decryption)
# ──────────────────────────────
def decrypt_bytes(wdek_b64: str, iv_b64: str, ciphertext_b64: str) -> bytes:
    """
    DB에 저장된 wdek, iv, ciphertext(Base64)를 복호화하여 원문 바이트 반환
    """
    try:
        # 1️⃣ Base64 디코딩
        wdek = base64.b64decode(wdek_b64)
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)

        # 2️⃣ 데이터키 복호화 (KMS)
        resp = kms.decrypt(CiphertextBlob=wdek)
        dek_plain = resp["Plaintext"]

        # 3️⃣ AES-GCM 복호화
        aesgcm = AESGCM(dek_plain)
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        return plaintext

    except Exception as e:
        current_app.logger.exception("decrypt_bytes_failed")
        raise

