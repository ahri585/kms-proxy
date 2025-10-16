import os, base64, json, uuid, io, re, hashlib, tempfile, shutil, urllib.parse
from typing import Optional, List, Tuple
from flask import (
    Blueprint, jsonify, request, render_template,
    send_file, send_from_directory, current_app
)
from sqlalchemy import text
from routes_auth import jwt_required, get_current_user
import boto3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from secrets import token_bytes
from app import db
from utils.file_parser import parse_any
from utils.masker import (
    process_pii, apply_mask_str, ALWAYS_MASK,
    handle_masking, VALID_KEYS, _normalize_allowed_types
)
from utils.crypto_core import encrypt_bytes, decrypt_bytes
from utils.audit_logger import log_audit
from docx import Document as DocxDocument
from pptx import Presentation
import pandas as pd
import openpyxl
import pdfplumber

# ──────────────────────────────
# 기본 설정
# ──────────────────────────────
REGION = os.getenv("AWS_REGION", "ap-northeast-2")
KMS_KEY_ID = os.getenv("KMS_KEY_ID", "alias/KEK")
crypto_bp = Blueprint("crypto", __name__, url_prefix="/api/crypto")
masked_bp = Blueprint("masked_files", __name__)  # ✅ 별도 Blueprint
kms = boto3.client("kms", region_name=REGION)

# ──────────────────────────────
# MIME 매핑
# ──────────────────────────────
MIMETYPES = {
    ".txt": "text/plain",
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".csv": "text/csv",
    ".json": "application/json",
    ".rtf": "application/rtf",
    ".odt": "application/vnd.oasis.opendocument.text",
    ".ppt": "application/vnd.ms-powerpoint",
    ".doc": "application/msword",
}

def guess_mime_by_ext(fname: str) -> str:
    ext = os.path.splitext(fname)[1].lower()
    return MIMETYPES.get(ext, "application/octet-stream")

# ──────────────────────────────
# DOCX / PPTX / XLSX 마스킹
# ──────────────────────────────
def mask_docx(in_path: str, out_path: str, allowed_types: Optional[List[str]]):
    doc = DocxDocument(in_path)
    for paragraph in doc.paragraphs:
        for run in paragraph.runs:
            run.text = apply_mask_str(run.text, allowed_types)
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for paragraph in cell.paragraphs:
                    for run in paragraph.runs:
                        run.text = apply_mask_str(run.text, allowed_types)
    doc.save(out_path)

def mask_pptx(in_path: str, out_path: str, allowed_types: Optional[List[str]]):
    prs = Presentation(in_path)
    for slide in prs.slides:
        for shape in slide.shapes:
            if hasattr(shape, "has_text_frame") and shape.has_text_frame:
                for para in shape.text_frame.paragraphs:
                    para.text = apply_mask_str(para.text, allowed_types)
    prs.save(out_path)

def mask_xlsx(in_path: str, out_path: str, allowed_types: Optional[List[str]]):
    try:
        wb = openpyxl.load_workbook(in_path, data_only=False, keep_links=False)
    except Exception as e:
        raise ValueError(f"엑셀 파일을 열 수 없습니다: {e}")

    for sheet in wb.worksheets:
        for row in sheet.iter_rows():
            for cell in row:
                if isinstance(cell.value, str):
                    cell.value = apply_mask_str(cell.value, allowed_types)

    tmp_out = out_path + ".tmp"
    wb.save(tmp_out)
    wb.close()
    shutil.move(tmp_out, out_path)

# ──────────────────────────────
# 암호화 + 마스킹
# ──────────────────────────────
@crypto_bp.post("/encrypt")
@jwt_required
def encrypt():
    try:
        current_app.logger.info("[encrypt] 시작")

        if "file" not in request.files:
            return jsonify({"ok": False, "error": "file_required"}), 400

        f = request.files["file"]
        raw = f.read()
        filename = f.filename or "upload.bin"
        name, ext = os.path.splitext(filename)
        token = str(uuid.uuid4())

        # --- 마스킹 타입 처리 ---
        mask_types = None
        if request.form.get("mask_types"):
            try:
                mask_types = json.loads(request.form["mask_types"])
            except Exception:
                mask_types = request.form.getlist("mask_types")

        if not mask_types:
            types_to_use = None
        else:
            norm = _normalize_allowed_types(mask_types)
            types_to_use = sorted(ALWAYS_MASK | set(norm)) or None

        parsed_text = parse_any(filename, raw)
        masked_text = None
        stats = {}
        if parsed_text:
            masked_text, _, stats = process_pii(parsed_text, types_to_use)

        tmp_dir = tempfile.mkdtemp(prefix="locku_")
        try:
            upload_tmp = os.path.join(tmp_dir, f"src{ext or '.bin'}")
            with open(upload_tmp, "wb") as w:
                w.write(raw)

            masked_dir = os.path.join(current_app.root_path, "static", "masked")
            os.makedirs(masked_dir, exist_ok=True)
            masked_name = f"{name}.masked{ext or '.bin'}"
            masked_path = os.path.join(masked_dir, masked_name)

            ext_lower = ext.lower()
            if ext_lower == ".docx":
                mask_docx(upload_tmp, masked_path, types_to_use)
            elif ext_lower == ".pptx":
                mask_pptx(upload_tmp, masked_path, types_to_use)
            elif ext_lower == ".xlsx":
                mask_xlsx(upload_tmp, masked_path, types_to_use)
            elif ext_lower in [".txt", ".csv", ".json", ".rtf", ".odt"]:
                with open(masked_path, "w", encoding="utf-8") as w:
                    w.write(masked_text or parsed_text or "")
            else:
                handle_masking(upload_tmp, masked_path, types_to_use)

            meta = {
                "filename": filename,
                "pii_count": sum(stats.values()) if stats else 0,
                "pii_stats": stats,
                "masked_file": f"/static/masked/{masked_name}",
            }

            enc = encrypt_bytes(raw, meta)
            db.session.execute(text("""
                INSERT INTO crypto_store.crypto_tokens
                    (token, wdek, iv, ciphertext, tag, meta)
                VALUES
                    (:token, :wdek, :iv, :ciphertext, :tag, CAST(:meta AS JSONB))
            """), {"token": token, **enc})
            db.session.commit()

            log_audit("crypto_tokens", "ENCRYPT", {"status": "SUCCESS", "token": token, "meta": meta})

            host = request.host or "lockument.duckdns.org"
            base_url = f"https://{host}"
            masked_url = f"{base_url}/static/masked/{urllib.parse.quote(masked_name)}"

            return jsonify({
                "ok": True,
                "token": token,
                "masked_file_url": masked_url,
                "pii_stats": stats,
            }), 200

        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    except Exception as e:
        db.session.rollback()
        current_app.logger.exception(f"[encrypt] 오류: {e}")
        log_audit("crypto_tokens", "ENCRYPT", {"status": "FAILED", "error": str(e)})
        return jsonify({"ok": False, "error": "encrypt_failed", "message": str(e)}), 500

# ──────────────────────────────
# 복호화
# ──────────────────────────────
@crypto_bp.post("/decrypt")
@jwt_required
def decrypt():
    try:
        body = request.get_json(silent=True) or request.form.to_dict()
        token = body.get("token")
        if not token:
            return jsonify({"ok": False, "error": "missing_token"}), 400

        row = db.session.execute(text("""
            SELECT wdek, iv, ciphertext, meta
            FROM crypto_store.crypto_tokens
            WHERE token = :token
        """), {"token": token}).fetchone()
        if not row:
            return jsonify({"ok": False, "error": "token_not_found"}), 404

        wdek_b64, iv_b64, ct_b64, raw_meta = row
        meta = json.loads(raw_meta) if isinstance(raw_meta, str) else (raw_meta or {})
        filename = meta.get("filename", "decrypted_file.bin")
        mime = guess_mime_by_ext(filename)

        plaintext = decrypt_bytes(wdek_b64, iv_b64, ct_b64)
        log_audit("crypto_tokens", "DECRYPT", {"status": "SUCCESS", "token": token, "meta": meta})

        bio = io.BytesIO(plaintext)
        bio.seek(0)
        response = send_file(
            bio,
            mimetype=mime,
            as_attachment=True,
            download_name=filename
        )
        response.headers["Content-Disposition"] = f"attachment; filename*=UTF-8''{urllib.parse.quote(filename)}"
        return response

    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("[decrypt] 실패")
        log_audit("crypto_tokens", "DECRYPT", {"status": "FAILED", "error": str(e)})
        return jsonify({"ok": False, "error": "decrypt_failed", "message": str(e)}), 500

# ──────────────────────────────
# 감사 로그
# ──────────────────────────────
@crypto_bp.get("/audit/recent")
def recent_audits():
    try:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        ua = request.headers.get("User-Agent", "unknown")
        user = None
        try:
            user = get_current_user()
        except Exception:
            pass

        current_app.logger.info(f"[audit/recent] accessed by user={getattr(user, 'username', None)} ip={ip}")

        sql = text("""
            SELECT op, row_new->>'status' AS status, changed_at
            FROM pii_audit.audit_logs
            ORDER BY changed_at DESC
            LIMIT 20;
        """)
        rows = db.session.execute(sql).mappings().all()

        logs = []
        for r in rows:
            entry = dict(r)
            entry["ip"] = ip
            entry["user_agent"] = ua
            entry["user"] = getattr(user, "username", None)
            logs.append(entry)

        return jsonify({"ok": True, "logs": logs})
    except Exception as e:
        current_app.logger.exception(f"[audit/recent] failed: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500

# ──────────────────────────────
# 최근 암호화 파일 목록
# ──────────────────────────────
@crypto_bp.get("/recent")
def list_recent_files():
    limit = request.args.get("limit", 20, type=int)
    sql = text("""
        SELECT meta->>'filename' AS filename, created_at
        FROM crypto_store.crypto_tokens
        ORDER BY created_at DESC
        LIMIT :limit;
    """)
    rows = db.session.execute(sql, {"limit": limit}).mappings().all()
    files = [
        {"filename": r["filename"], "created_at": r["created_at"].isoformat() if r["created_at"] else None}
        for r in rows
    ]
    return jsonify({"ok": True, "files": files})

# ──────────────────────────────
# ✅ 정식 마스킹 파일 다운로드 (prefix 없음)
# ──────────────────────────────
@masked_bp.route("/static/masked/<path:filename>")
def serve_masked_public(filename):
    """React 및 Nginx에서 접근하는 공개 다운로드용"""
    decoded = urllib.parse.unquote(filename)
    safe = os.path.normpath(decoded).replace("\\", "/")

    if safe.startswith("../"):
        return jsonify({"ok": False, "error": "invalid_path"}), 400

    masked_dir = os.path.join(current_app.root_path, "static", "masked")
    file_path = os.path.join(masked_dir, safe)

    current_app.logger.info(f"[serve_masked_public] 요청됨: {file_path}")

    if not os.path.exists(file_path):
        current_app.logger.warning(f"[serve_masked_public] 파일 없음: {file_path}")
        return jsonify({"ok": False, "error": "file_not_found"}), 404

    mime = guess_mime_by_ext(safe)
    return send_from_directory(
        masked_dir,
        safe,
        as_attachment=True,
        mimetype=mime,
        download_name=os.path.basename(safe)
    )

