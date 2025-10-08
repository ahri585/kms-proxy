import os, base64, json, uuid, io, re, hashlib, tempfile, shutil
from typing import Optional, List, Tuple
from flask import Blueprint, jsonify, request, render_template, send_from_directory, send_file, current_app,make_response, g
from sqlalchemy import text
from routes_auth import jwt_required,get_current_user
import boto3, urllib.parse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from secrets import token_bytes
from app import db
from routes_auth import jwt_required  # 중복 import
from utils.file_parser import parse_any
from utils.masker import process_pii, apply_mask_str, ALWAYS_MASK, handle_masking, VALID_KEYS, _normalize_allowed_types
from utils.crypto_core import encrypt_bytes, decrypt_bytes
from utils.audit_logger import log_audit
# 파일 파싱 라이브러리
import pdfplumber
import docx
from docx import Document as DocxDocument
import openpyxl
import pandas as pd
from pptx import Presentation  # PPTX 지원

# ═══════════════════════════════════════════
# 환경설정
# ═══════════════════════════════════════════
REGION = os.getenv("AWS_REGION", "ap-northeast-2")
KMS_KEY_ID = os.getenv("KMS_KEY_ID", "alias/KEK")

crypto_bp = Blueprint("crypto", __name__)
kms = boto3.client("kms", region_name=REGION)

# ═══════════════════════════════════════════
# 확장자별 MIME
# ═══════════════════════════════════════════
MIMETYPES = {
    ".txt":  "text/plain",
    ".pdf":  "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".csv":  "text/csv",
    ".json": "application/json",
    ".rtf":  "application/rtf",
    ".odt":  "application/vnd.oasis.opendocument.text",
    ".ppt":  "application/vnd.ms-powerpoint",
    ".doc":  "application/msword",
}

def guess_mime_by_ext(fname: str) -> str:
    ext = os.path.splitext(fname)[1].lower()
    return MIMETYPES.get(ext, "application/octet-stream")

# ═══════════════════════════════════════════
# 파일 형태 보존 마스킹(DOCX/PPTX 등)
# ═══════════════════════════════════════════
def mask_docx(in_path: str, out_path: str, allowed_types: Optional[List[str]]):
    doc = DocxDocument(in_path)

    # 본문 문단
    for p in doc.paragraphs:
        p.text = apply_mask_str(p.text, allowed_types)

    # 표
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    p.text = apply_mask_str(p.text, allowed_types)

    # (선택) 헤더/푸터
    for section in doc.sections:
        if section.header:
            for p in section.header.paragraphs:
                p.text = apply_mask_str(p.text, allowed_types)
        if section.footer:
            for p in section.footer.paragraphs:
                p.text = apply_mask_str(p.text, allowed_types)

    doc.save(out_path)

def mask_pptx(in_path: str, out_path: str, allowed_types: Optional[List[str]]):
    prs = Presentation(in_path)
    for slide in prs.slides:
        for shape in slide.shapes:
            if hasattr(shape, "has_text_frame") and shape.has_text_frame:
                tf = shape.text_frame
                for para in tf.paragraphs:
                    para.text = apply_mask_str(para.text, allowed_types)
    prs.save(out_path, g)

# ═══════════════════════════════════════════
# API
# ═══════════════════════════════════════════
@crypto_bp.get("/api/mask-types")
def list_mask_types():
    return jsonify({"ok": True, "types": sorted(PII_RULES_MAP.keys())}), 200

@crypto_bp.post("/api/encrypt")
@jwt_required
def encrypt():
    try:
        if "file" not in request.files:
            return jsonify({"ok": False, "error": "file_required"}), 400

        f = request.files["file"]
        raw = f.read()
        # 원본 파일명 보존 (확장자 포함)
        original_filename = f.filename if f.filename else "upload.bin"
        filename = original_filename.strip() or "upload.bin"
        
        # 디버깅 로그 추가
        current_app.logger.info(f"Original filename: {filename}")
        
        name, ext = os.path.splitext(filename)
        token = str(uuid.uuid4())

        # --- 프론트에서 전달한 마스킹 타입 가져오기 ---
        mask_types = None
        if request.form.get("mask_types"):
            try:
                mask_types = json.loads(request.form["mask_types"])
            except Exception:
                mask_types = request.form.getlist("mask_types")
        elif request.is_json:
            body = request.get_json(silent=True) or {}
            mask_types = body.get("mask_types")

        # 타입 최종 집합 계산
        if not mask_types:
            types_to_use = None  # process_pii(None) 시 전체 적용
        else:
            norm = _normalize_allowed_types(mask_types)
            types_to_use = sorted(ALWAYS_MASK | set(norm)) or None

        # 미리보기/통계용 텍스트
        parsed_text = parse_any(filename, raw)
        current_app.logger.info(f"Parsed text preview: {parsed_text[:500]!r}")
        if parsed_text:
            masked_preview_text, _, stats = process_pii(parsed_text, types_to_use)
            masked_preview_bytes = masked_preview_text.encode("utf-8", "ignore")
        else:
            masked_preview_bytes = b""
            stats = {}

        # 실제로 원본을 임시파일로 만든 뒤 형태 보존 마스킹에 필요)
        tmp_dir = tempfile.mkdtemp(prefix="locku_")
        try:
            upload_tmp = os.path.join(tmp_dir, f"src{ext or '.bin'}")
            with open(upload_tmp, "wb") as w:
                w.write(raw)

            # 마스킹 파일 저장: 확장자 보존 / 일반 형태는 .txt로 대체
            masked_dir = os.path.join("static", "masked")
            os.makedirs(masked_dir, exist_ok=True)
            masked_name = f"{(name or 'upload')}.mask{ext or '.bin'}"
            masked_path = os.path.join(masked_dir, masked_name)

            final_masked_name = handle_masking(upload_tmp, masked_path, types_to_use)
            final_masked_path = os.path.join(masked_dir, final_masked_name)

            # DB 저장 - filename에 원본 파일명(확장자 포함) 저장
            meta = {
                "filename": filename,  # 확장자 포함된 원본 파일명
                "pii_count": sum(stats.values()) if stats else 0,
                "pii_stats": stats,
                "masked_file": f"/upload/masked/{final_masked_name}",
            }
            
            # 디버깅: meta 확인
            current_app.logger.info(f"Saving meta: {meta}")
            
            enc = encrypt_bytes(raw, meta)
            sql = text("""
                INSERT INTO crypto_store.crypto_tokens
                    (token, wdek, iv, ciphertext, tag, meta)
                VALUES
                    (:token, :wdek, :iv, :ciphertext, :tag, CAST(:meta AS JSONB))
            """)
            db.session.execute(sql, {
                "token": token,
                **enc
            })
            db.session.commit()

            # 감사 로그 기록
            log_audit(
                    "crypto_tokens",
                    "ENCRYPT",
                    {"status": "SUCCESS", "token": token, "meta": meta},
            )

            # 실제 적용 규칙 목록
            effective_mask_types = sorted(VALID_KEYS) if types_to_use is None else list(types_to_use)

            return jsonify({
                "ok": True,
                "token": token,
                "masked_file_url": f"/upload/masked/{final_masked_name}",
                "pii_stats": stats,
                "masked_preview": masked_preview_bytes[:500].decode("utf-8", "ignore"),
                "effective_mask_types": effective_mask_types,
            }), 200

        finally:
            try:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass

    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("encrypt_failed")
        
        # 실패 시 감사 로그
        log_audit(
                "crypto_tokens",
                "ENCRYPT",
                {"status": "FAILED", "error": str(e)},
        )
        return jsonify({"ok": False, "error": "encrypt_failed", "message": str(e)}), 500


@crypto_bp.post("/api/decrypt")
@jwt_required
def decrypt():
    """
    기본: 원본 파일 스트림으로 반환(다운로드)
    ?mode=json → 기존처럼 base64 JSON 응답
    """
    try:
        body = request.get_json(silent=True)
        if not body:
            body = request.form.to_dict()

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

        # 메타(파일명) 파싱
        meta = {}
        if isinstance(raw_meta, str):
            try:
                meta = json.loads(raw_meta)
            except Exception:
                pass
        elif isinstance(raw_meta, dict):
            meta = raw_meta
            
        filename = meta.get("filename", "decrypted_file.bin")
        
        # 디버깅 로그
        current_app.logger.info(f"Retrieved meta: {meta}")
        current_app.logger.info(f"Filename: {filename}")
        
        mime = guess_mime_by_ext(filename)
        current_app.logger.info(f"MIME type: {mime}")

        # 복호화
        plaintext = decrypt_bytes(wdek_b64, iv_b64, ct_b64)

        # 감사 로그
        log_audit(
            "crypto_tokens",
            "DECRYPT",
            {"status": "SUCCESS", "token": token, "meta": meta},
        )
        
        # 모드 분기
        mode = (request.args.get("mode") or "").lower()
        if mode == "json":
            return jsonify({
                "ok": True,
                "result": base64.b64encode(plaintext).decode(),
                "filename": filename,
            }), 200

        # 파일 스트림 응답
        bio = io.BytesIO(plaintext)
        bio.seek(0)

        # Flask 버전에 따라 download_name 또는 attachment_filename 사용
        try:
            # Flask 2.0+
            response = send_file(
                bio,
                mimetype=mime,
                as_attachment=True,
                download_name=filename
            )
        except TypeError:
            # Flask 1.x
            response = send_file(
                bio,
                mimetype=mime,
                as_attachment=True,
                attachment_filename=filename
            )
        
        # UTF-8 파일명 지원을 위한 헤더
        response.headers["Content-Disposition"] = (
            f"attachment; filename*=UTF-8''{urllib.parse.quote(filename)}"
        )

        return response

    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("decrypt_failed")

        # 실패 시 감사 로그
        log_audit(
            "crypto_tokens",
            "DECRYPT",
            {"status": "FAILED", "error": str(e)},
        )
        return jsonify({"ok": False, "error": "decrypt_failed", "message": str(e)}), 500


# 업로드 페이지
@crypto_bp.route("/upload/")
def upload_page():
    return render_template("upload.html")


# 마스킹 파일 다운로드 (MIME 지원 + 경로 안전)
@crypto_bp.get("/upload/masked/<path:fname>")
def download_masked(fname):
    safe = os.path.normpath(fname).replace("\\", "/")
    if safe.startswith("../"):
        return "Invalid path", 400
    mime = guess_mime_by_ext(safe)
    return send_from_directory("static/masked", safe, as_attachment=True, mimetype=mime)


@crypto_bp.get("/api/audit/recent")
@jwt_required
def recent_audits():
    user = get_current_user()

    if user.role != "admin":
        return jsonify({"ok": False, "error": "forbidden", "message": "관리자만 접근 가능합니다."}), 403
    sql = text("""
        SELECT
            op,
            row_new->>'status' AS status,
            row_new->'meta'->>'user_id' AS user_id,
            row_new->'meta'->>'client_ip' AS ip,
            row_new->'meta'->>'user_agent' AS browser,
            changed_at
        FROM pii_audit.audit_logs
        ORDER BY changed_at DESC
        LIMIT 20;
    """)
    rows = db.session.execute(sql).mappings().all()
    return jsonify({"ok": True, "logs": [dict(r) for r in rows]})


@crypto_bp.get("/recent/view")
def view_recent_logs():
    """관리자 로그 페이지"""
    return render_template("recent_logs.html")
