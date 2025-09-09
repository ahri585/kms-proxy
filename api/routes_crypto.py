import os, base64, json, uuid, io, re, hashlib
from flask import Blueprint, jsonify, request, render_template, send_from_directory
from sqlalchemy import text
import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from secrets import token_bytes
from app import db   # create_app에서 초기화한 db 객체 가져오기

# ▼▼ 신규: 포맷별 파서에 필요한 라이브러리
import pdfplumber      # PDF 텍스트 추출
import docx            # DOCX 텍스트 추출
import openpyxl        # XLSX 텍스트 추출
import pandas as pd    # CSV 파싱

# 환경 변수
REGION = os.getenv("AWS_REGION", "ap-northeast-2")
KMS_KEY_ID = os.getenv("KMS_KEY_ID", "alias/KEK")

crypto_bp = Blueprint("crypto", __name__)
kms = boto3.client("kms", region_name=REGION)

# 허용 확장자(텍스트 파싱용)
ALLOWED_EXTS = [".pdf",".docx",".xlsx",".csv",".txt",".json",".rtf",".odt",".pptx"]


# ----------------------------------
# 0) 공통 유틸
# ----------------------------------
def sha256_hex(b: bytes) -> str:
    h = hashlib.sha256(); h.update(b); return h.hexdigest()


# ----------------------------------
# 1) 포맷별 파서
#    - 파일 바이트 -> 읽기 쉬운 문자열
# ----------------------------------
def parse_pdf(b: bytes) -> str:
    try:
        with pdfplumber.open(io.BytesIO(b)) as pdf:
            return "\n".join((p.extract_text() or "") for p in pdf.pages)
    except Exception:
        return ""

def parse_docx(b: bytes) -> str:
    try:
        d = docx.Document(io.BytesIO(b))
        return "\n".join([p.text for p in d.paragraphs if p.text])
    except Exception:
        return ""

def parse_xlsx(b: bytes) -> str:
    try:
        wb = openpyxl.load_workbook(io.BytesIO(b), data_only=True)
        out = []
        for s in wb.sheetnames:
            for row in wb[s].iter_rows(values_only=True):
                out.append(" ".join([str(c) for c in row if c]))
        return "\n".join(out)
    except Exception:
        return ""

def parse_csv(b: bytes) -> str:
    for enc in ("utf-8","cp949"):
        try:
            return pd.read_csv(io.BytesIO(b), encoding=enc).to_string(index=False)
        except Exception:
            continue
    try:
        return b.decode("utf-8","ignore")
    except Exception:
        return ""

def parse_txt(b: bytes) -> str:
    try:
        return b.decode("utf-8","ignore")
    except Exception:
        return ""

def parse_json_text(b: bytes) -> str:
    try:
        return json.dumps(json.loads(b.decode("utf-8","ignore")), ensure_ascii=False, indent=2)
    except Exception:
        return parse_txt(b)

def parse_any(filename: str, b: bytes) -> str:
    fn = filename.lower()
    if fn.endswith(".pdf"):  return parse_pdf(b)
    if fn.endswith(".docx"): return parse_docx(b)
    if fn.endswith(".xlsx"): return parse_xlsx(b)
    if fn.endswith(".csv"):  return parse_csv(b)
    if fn.endswith(".json"): return parse_json_text(b)
    if fn.endswith(".txt"):  return parse_txt(b)
    # 그 외 확장자는 파싱 스킵
    return ""


# ----------------------------------
# 2) PII 탐지/부분 마스킹
#    - 텍스트는 보존, 민감부분만 치환
#    - meta에 원문은 저장하지 않고 해시만 보관
# ----------------------------------
PII_RULES = [
    # 주민등록번호
    (re.compile(r"\b\d{6}-\d{7}\b"), "rrn",
     lambda s: "######-*******"),
    # 휴대전화
    (re.compile(r"\b01[016789][-\s]?\d{3,4}[-\s]?\d{4}\b"), "phone",
     lambda s: (lambda d: (d[:3] + "-****-" + d[-4:]) if len(d) >= 10 else "010-****-****")(re.sub(r"\D","",s))),
    # 이메일
    (re.compile(r"\b([A-Za-z0-9._%+-])([A-Za-z0-9._%+-]*)(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"), "email",
     lambda s: (s[0] + "***" + s[s.find('@'):]) if "@" in s else s),
    # 카드/계좌(10~19자리 숫자)
    (re.compile(r"\b\d{10,19}\b"), "card_or_acct",
     lambda s: s[:6] + "******" + s[-4:] if len(s) >= 10 else "******"),
    # 인증키/비번
    (re.compile(r"(?i)\b(password|api[_ ]?key|token)\s*[:=]\s*['\"]?[^'\",\s]+['\"]?"), "auth",
     lambda s: re.sub(r'(?<=[:=]\s?)(["\'])?[^"\',\s]+(["\'])?', "[SECRET]", s)),
    # 주소(시/도 + 구/군/시까지만)
    (re.compile(r"[가-힣]+(?:시|도)\s?[가-힣]+(?:구|군|시)[^\n]*"), "address",
     lambda s: re.sub(r"([가-힣]+(?:시|도)\s?[가-힣]+(?:구|군|시)).*", r"\1 ****", s)),
]

def process_pii(text: str):
    """
    입력 텍스트에서 민감정보만 찾아 부분 마스킹.
    반환:
      masked_text: 치환된 전체 텍스트
      hits: [{type, masked, sha256}]  (원문은 저장/응답하지 않음)
      stats: {type: count}
    """
    hits = []
    stats = {}
    masked = text

    for pattern, label, mask_fn in PII_RULES:
        def repl(m):
            orig = m.group(0)
            masked_val = mask_fn(orig)
            hits.append({
                "type": label,
                "masked": masked_val,
                "sha256": sha256_hex(orig.encode("utf-8","ignore")),
            })
            stats[label] = stats.get(label, 0) + 1
            return masked_val
        masked = pattern.sub(repl, masked)

    return masked, hits, stats


# --- DB 핑 ---
@crypto_bp.get("/api/dbping")
def dbping():
    with db.engine.connect() as conn:
        row = conn.execute(
            text("select current_database(), current_user, current_schemas(true), now()")
        ).fetchone()
        return {
            "db": row[0],
            "user": row[1],
            "search_path": row[2],
            "now": str(row[3])
        }, 200


# --- KMS 테스트 ---
@crypto_bp.get("/api/kms-test")
def kms_test():
    try:
        res = kms.generate_data_key(KeyId=KMS_KEY_ID, KeySpec="AES_256")
        ct_len = len(res.get("CiphertextBlob", b"") or b"")
        return jsonify({"ok": True, "ciphertext_blob_len": ct_len}), 200
    except ClientError as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# --- 암호화 (파일 업로드 + PII 파싱·부분 마스킹 + 토큰 발급) ---
@crypto_bp.post("/api/encrypt")
def encrypt():
    try:
        if "file" not in request.files:
            return jsonify({"ok": False, "error": "file_required"}), 400

        f = request.files["file"]
        raw = f.read()
        filename = (f.filename or "upload.bin").strip() or "upload.bin"
        name, ext = os.path.splitext(filename)
        token = str(uuid.uuid4())

        # 1) PII 파싱 + 부분 마스킹 (텍스트 파일/문서만 시도)
        parsed_text = parse_any(filename, raw)
        if parsed_text:  # 파싱 성공 시 텍스트 기반 마스킹
            masked_text, hits, stats = process_pii(parsed_text)
            masked_bytes = masked_text.encode("utf-8","ignore")
        else:
            # 바이너리 등 파싱 불가 시: 길이 보존형 별표 마스킹(데모)
            try:
                txt = raw.decode("utf-8","ignore")
                masked_bytes = ("*" * len(txt)).encode("utf-8")
            except Exception:
                masked_bytes = b"*" * len(raw)
            hits, stats = [], {}

        # 2) 마스킹 파일 저장 (원본파일명.mask.ext)
        masked_dir = os.path.join("static", "masked")
        os.makedirs(masked_dir, exist_ok=True)
        masked_name = f"{(name or 'upload')}.mask{ext or '.bin'}"
        with open(os.path.join(masked_dir, masked_name), "wb") as out:
            out.write(masked_bytes)

        # 3) KMS에서 DEK 발급
        resp = kms.generate_data_key(KeyId=KMS_KEY_ID, KeySpec="AES_256")
        dek_plain = resp["Plaintext"]
        wdek = resp["CiphertextBlob"]

        # 4) AES-GCM 암호화 (파일 원문 raw 전체)
        iv = token_bytes(12)
        aesgcm = AESGCM(dek_plain)
        ciphertext = aesgcm.encrypt(iv, raw, None)  # aad=None

        # 5) 토큰 + CryptoPackage DB 저장 (meta에 PII 요약 포함)
        meta = {
            "filename": filename,
            "pii_count": sum(stats.values()) if stats else 0,
            "pii_stats": stats,                    # 타입별 개수
            "masked_file": f"/static/masked/{masked_name}"
        }

        sql = text("""
            INSERT INTO crypto_tokens (token, wdek, iv, ciphertext, tag, meta)
            VALUES (:token, :wdek, :iv, :ciphertext, :tag, CAST(:meta AS JSONB))
        """)
        db.session.execute(sql, {
            "token": token,
            "wdek": base64.b64encode(wdek).decode(),
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "tag": "",
            "meta": json.dumps(meta, ensure_ascii=False),
        })
        db.session.commit()

        # 6) 응답 (미리보기/요약 제공, 원문/PII 원문은 절대 미포함)
        return jsonify({
            "ok": True,
            "token": token,
            "masked_file_url": meta["masked_file"],
            "pii_count": meta["pii_count"],
            "pii_stats": meta["pii_stats"],
            # 파싱 성공 시 일부 미리보기 (텍스트만)
            "masked_preview": (masked_bytes[:500].decode("utf-8","ignore") if parsed_text else None)
        }), 200

    except ClientError as e:
        db.session.rollback()
        return jsonify({
            "ok": False,
            "error": "kms_unavailable",
            "message": str(e)
        }), 500
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "ok": False,
            "error": "encrypt_failed",
            "message": str(e)
        }), 500


# --- 복호화 (토큰 기반) ---
@crypto_bp.post("/api/decrypt")
def decrypt():
    try:
        body = request.get_json(force=True, silent=True) or {}
        token = body.get("token")
        if not token:
            return jsonify({"ok": False, "error": "missing 'token'"}), 400

        # 1) DB에서 패키지 조회
        row = db.session.execute(text("""
            SELECT wdek, iv, ciphertext, meta FROM crypto_tokens WHERE token = :token
        """), {"token": token}).fetchone()

        if not row:
            return jsonify({"ok": False, "error": "token_not_found"}), 404

        wdek = base64.b64decode(row[0])
        iv = base64.b64decode(row[1])
        ciphertext = base64.b64decode(row[2])
        
        raw_meta = row[3]
        if isinstance(raw_meta, (dict, list)):
            meta = raw_meta
        elif isinstance(raw_meta, (bytes, bytearray)):
            meta = json.loads(raw_meta.decode("utf-8", "ignore"))
        elif isinstance(raw_meta, str):
            meta = json.loads(raw_meta)
        else:
            meta = {}
        # 2) KMS 복호화
        resp = kms.decrypt(CiphertextBlob=wdek)
        dek_plain = resp["Plaintext"]

        # 3) AES-GCM 복호화
        aesgcm = AESGCM(dek_plain)
        plaintext = aesgcm.decrypt(iv, ciphertext, None)

        orig_name = meta.get("filename", "decrypted_file")

        return jsonify({
            "ok": True,
            "result": base64.b64encode(plaintext).decode(),
            "filename": orig_name
        }), 200

    except ClientError as e:
        return jsonify({
            "ok": False,
            "error": "kms_unavailable",
            "message": str(e)
        }), 500
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": "decrypt_failed",
            "message": str(e)
        }), 500


# --- 업로드 페이지 (암호화/복호화 UI) ---
@crypto_bp.route("/upload")
def upload_page():
    return render_template("upload.html")


# --- 마스킹 파일 무조건 다운로드 ---
@crypto_bp.get("/static/masked/<path:fname>")
def download_masked(fname):
    return send_from_directory("static/masked", fname, as_attachment=True)

