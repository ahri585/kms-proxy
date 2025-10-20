# utils/encryptor.py
import os
import json
import base64
import struct
import tempfile
from typing import Optional, Tuple, Dict, Any

import boto3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from utils.audit_logger import log_audit

# ─────────────────────────────────────────
# 환경설정
# ─────────────────────────────────────────
REGION = os.getenv("AWS_REGION", "ap-northeast-2")
KMS_KEY_ID = os.getenv("KMS_KEY_ID", "alias/KEK")
kms = boto3.client("kms", region_name=REGION)

# ─────────────────────────────────────────
# Lockument 컨테이너 포맷 (파일만으로 복호화 가능)
# MAGIC(5B) | VER(1B) | HEADER_LEN(4B, BE) | HEADER_JSON | CIPHERTEXT(GCM CT||TAG)
# ─────────────────────────────────────────
MAGIC = b"LKMT1"
VER = 1


def _pack_container(header: Dict[str, Any], ciphertext: bytes) -> bytes:
    """
    컨테이너 바이너리로 직렬화.
    header 는 JSON으로 직렬화되며, UTF-8 인코딩/공백제거.
    """
    hjson = json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return MAGIC + bytes([VER]) + struct.pack(">I", len(hjson)) + hjson + ciphertext


def _unpack_container(blob: bytes) -> Optional[Tuple[Dict[str, Any], bytes]]:
    """
    컨테이너 바이너리를 파싱. 컨테이너가 아니면 None.
    반환: (header_dict, ciphertext)
    """
    if len(blob) < 10 or blob[:5] != MAGIC:
        return None
    ver = blob[5]
    if ver != VER:
        raise ValueError(f"Unsupported container version: {ver}")
    hlen = struct.unpack(">I", blob[6:10])[0]
    hstart, hend = 10, 10 + hlen
    if hend > len(blob):
        raise ValueError("Invalid container: header length out of bounds")
    hjson = blob[hstart:hend]
    try:
        header = json.loads(hjson.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Invalid container header JSON: {e}")
    ciphertext = blob[hend:]
    return header, ciphertext


def parse_container(blob: bytes) -> Optional[Tuple[Dict[str, Any], bytes]]:
    """
    외부에서 사용할 수 있는 컨테이너 파서 (파일만 업로드 복호화용).
    컨테이너가 아니면 None 을 반환.
    """
    return _unpack_container(blob)


def encrypt_file(file_path: str, user_id: int, kms_key_id: Optional[str] = None) -> Dict[str, Any]:
    """
    파일을 AWS KMS 기반 AES-GCM으로 암호화.

    반환:
      {
        "enc_path": "<...>.enc",    # 기존 방식(순수 암호문) - 하위호환 유지
        "lkm_path": "<...>.lkm",    # 신규 컨테이너(파일만으로 복호화 가능)
        "metadata": {
            "alg": "AES-256-GCM",
            "kms_key_id": "...",
            "iv": "<base64>",
            "enc_dek": "<base64>",  # KMS로 암호화된 데이터 키
            "cipher_len": <int>,
            "filename": "<원본파일명>"
            # (옵션) "aad": "lockument:v1"
        }
      }
    """
    kms_key_id = kms_key_id or KMS_KEY_ID
    if not kms_key_id:
        raise ValueError("KMS_KEY_ID is not set.")

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    # 1) 원본 읽기
    with open(file_path, "rb") as f:
        plaintext = f.read()

    # 2) KMS DataKey 생성 (Envelope Encryption)
    gen = kms.generate_data_key(KeyId=kms_key_id, KeySpec="AES_256")
    plain_key: bytes = gen["Plaintext"]
    enc_dek: bytes = gen["CiphertextBlob"]  # 암호화된 DEK(EncDEK)

    # 3) AES-GCM 암호화
    iv = os.urandom(12)
    aesgcm = AESGCM(plain_key)
    # 필요 시 정책 버전 등 AAD 사용: aad = b"lockument:v1"
    ciphertext = aesgcm.encrypt(iv, plaintext, None)

    # 4) 메타데이터 구성 (복호화 핵심 필드)
    header = {
        "alg": "AES-256-GCM",
        "kms_key_id": kms_key_id,
        "iv": base64.b64encode(iv).decode(),
        "enc_dek": base64.b64encode(enc_dek).decode(),
        "cipher_len": len(ciphertext),
        "filename": os.path.basename(file_path),
        # "aad": "lockument:v1",
        "version": 1,
    }

    # 5) 산출물 저장: .enc(순수) + .lkm(컨테이너)
    dir_ = os.path.dirname(file_path) or "."
    base = os.path.basename(file_path)

    enc_path = os.path.join(dir_, base + ".enc")
    with open(enc_path, "wb") as wf:
        wf.write(ciphertext)

    container_bytes = _pack_container(header, ciphertext)
    lkm_path = os.path.join(dir_, base + ".lkm")
    with open(lkm_path, "wb") as wf:
        wf.write(container_bytes)

    # 6) 감사 로그
    log_audit(
        "crypto_store",
        "ENCRYPT_FILE_FULL",
        {"status": "SUCCESS", "user_id": user_id, "filename": base, "metadata": header},
    )

    return {
        "enc_path": enc_path,   # 기존 로직이 이 키를 사용하므로 유지
        "lkm_path": lkm_path,   # 신규 컨테이너 파일 (업로드만으로 복호화 가능)
        "metadata": header,     # UI/백업용 메타 JSON
    }

