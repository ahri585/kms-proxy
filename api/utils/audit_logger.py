# utils/audit_logger.py
from __future__ import annotations

import json
import datetime as dt
from typing import Any, Dict, Optional

from flask import request, current_app, g
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app import db


def _safe_request_ip() -> str:
    try:
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        xr = request.headers.get("X-Real-IP")
        if xr:
            return xr
        return request.remote_addr or "unknown"
    except Exception:
        return "unknown"


def _safe_user_agent() -> str:
    try:
        return request.headers.get("User-Agent", "unknown")
    except Exception:
        return "unknown"


def _safe_user_id() -> str:
    try:
        return str(getattr(g, "user_id", None) or "anonymous")
    except Exception:
        return "anonymous"


def _make_meta(extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    meta = {
        "client_ip": _safe_request_ip(),
        "user_agent": _safe_user_agent(),
        "user_id": _safe_user_id(),
        "timestamp": dt.datetime.utcnow().isoformat(),
    }
    if extra:
        meta.update(extra)
    return meta


def log_audit(
    tbl_name: str,
    op: str,
    new_data: Dict[str, Any],
    old_data: Optional[Dict[str, Any]] = None,
    extra_meta: Optional[Dict[str, Any]] = None,
) -> None:
    """
    tbl_name: 논리적 테이블/도메인 이름(예: 'crypto_store')
    op:       액션(예: 'ENCRYPT', 'DECRYPT_FILE_FULL')
    new_data: {"status": "SUCCESS", ...} 형태 권장 (recent API가 status를 읽음)
    """
    try:
        base_meta = _make_meta(extra_meta)
        # row_new/meta 합치기 + tbl_name을 meta에 보존
        row_new = dict(new_data or {})
        meta = dict(base_meta)
        # 사용자가 넣은 meta가 dict이면 merge
        if isinstance(row_new.get("meta"), dict):
            m = dict(row_new["meta"])
            m.update(meta)
            meta = m
        meta["tbl_name"] = tbl_name
        row_new["meta"] = meta

        row_old = dict(old_data or {})

        # 세션과 분리된 엔진 트랜잭션으로 독립 커밋
        with db.engine.begin() as conn:
            conn.execute(
                text("""
                    INSERT INTO pii_audit.audit_logs (op, row_new, row_old)
                    VALUES (:op, CAST(:new AS JSONB), CAST(:old AS JSONB))
                """),
                {
                    "op": op,
                    "new": json.dumps(row_new, ensure_ascii=False),
                    "old": json.dumps(row_old, ensure_ascii=False),
                },
            )

        try:
            current_app.logger.info(
                f"[AUDIT_LOG] {op} by user={base_meta.get('user_id')} ip={base_meta.get('client_ip')}"
            )
        except Exception:
            pass

    except SQLAlchemyError as e:
        try:
            current_app.logger.warning(f"[AUDIT_LOG_FAIL] DB error: {e}")
        except Exception:
            pass
    except Exception as e:
        try:
            current_app.logger.warning(f"[AUDIT_LOG_FAIL] {e}")
        except Exception:
            pass


def log_encrypt(
    new_data: Dict[str, Any],
    old_data: Optional[Dict[str, Any]] = None,
    tbl_name: str = "crypto_store",
    extra_meta: Optional[Dict[str, Any]] = None,
) -> None:
    log_audit(tbl_name=tbl_name, op="ENCRYPT", new_data=new_data, old_data=old_data, extra_meta=extra_meta)


def log_decrypt(
    new_data: Dict[str, Any],
    old_data: Optional[Dict[str, Any]] = None,
    tbl_name: str = "crypto_store",
    extra_meta: Optional[Dict[str, Any]] = None,
) -> None:
    log_audit(tbl_name=tbl_name, op="DECRYPT", new_data=new_data, old_data=old_data, extra_meta=extra_meta)


def log_mask(
    new_data: Dict[str, Any],
    old_data: Optional[Dict[str, Any]] = None,
    tbl_name: str = "mask_results",
    extra_meta: Optional[Dict[str, Any]] = None,
) -> None:
    log_audit(tbl_name=tbl_name, op="MASK", new_data=new_data, old_data=old_data, extra_meta=extra_meta)

