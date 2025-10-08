import os, re, json, hashlib, openpyxl, pdfplumber
from pptx import Presentation
from docx import Document as DocxDocument
from typing import Optional, List, Tuple

# ──────────────────────────────
# 유틸: SHA256 해시
# ──────────────────────────────
def sha256_hex(b: bytes) -> str:
    """SHA256 해시 (민감정보 식별용)"""
    return hashlib.sha256(b).hexdigest()

# ──────────────────────────────
# 민감정보(PII) 정규식 패턴 정의
# ──────────────────────────────
AUTH_VALUE_SUB_RE = re.compile(
    r'((password|api[_ ]?key|token)\s*[:=]\s*)([\'"]?)[^\'",\s]+([\'"]?)',
    re.IGNORECASE
)

PII_RULES_MAP = {
    "rrn": (
        re.compile(r"\b\d{6}-\d{7}\b"),
        lambda s: "######-*******"
    ),
    "email": (
        re.compile(r"\b([A-Za-z0-9._%+-])([A-Za-z0-9._%+-]*)(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"),
        lambda s: (s[0] + "***" + s[s.find('@'):]) if "@" in s else s
    ),
    "card_or_acct": (
        re.compile(r"\b\d{10,19}\b"),
        lambda s: (s[:6] + "******" + s[-4:]) if len(s) >= 10 else "******"
    ),
    "auth": (
        re.compile(r"\b(password|api[_ ]?key|token)\s*[:=]\s*['\"]?[^'\",\s]+['\"]?", re.IGNORECASE),
        lambda s: AUTH_VALUE_SUB_RE.sub(r"\1[SECRET]", s)
    ),
    "passport": (
        re.compile(r"\b[A-Z][0-9]{8}\b", re.IGNORECASE),
        lambda s: s[0] + "********"
    ),
    "license": (
        re.compile(r"\b\d{2}-\d{2}-\d{6}-\d{2}\b|\b\d{2}-\d{6}-\d{2}-\d{2}\b"),
        lambda s: re.sub(r"\d", "*", s)
    ),
    "foreign_id": (
        re.compile(r"\b\d{6}-[5-8]\d{6}\b"),
        lambda s: "######-*******"
    ),
    # 전화번호 및 주소 추가
    "phone": (
        re.compile(r"\b(01[016789]-?\d{3,4}-?\d{4})\b"),
        lambda s: s[:3] + "-****-" + s[-4:]
    ),
    "address": (
        re.compile(r"[가-힣A-Za-z0-9\s]+(로|길)\s?\d{0,3}"),
        lambda s: s[:2] + "****"
    ),
}

ALWAYS_MASK = {"rrn", "passport", "license", "foreign_id", "auth"}
VALID_KEYS = set(PII_RULES_MAP.keys())

# ──────────────────────────────
# 문자열 마스킹 로직
# ──────────────────────────────
def process_pii(text: str, allowed_types: Optional[List[str]] = None) -> Tuple[str, list, dict]:
    """
    텍스트에서 개인정보(PII) 감지 및 마스킹 처리
    """
    hits, stats, masked = [], {}, text
    types_to_use = list(set((allowed_types or VALID_KEYS)) | ALWAYS_MASK)

    for label in types_to_use:
        pattern, mask_fn = PII_RULES_MAP[label]

        def repl(m):
            orig = m.group(0)
            masked_val = mask_fn(orig)
            hits.append({
                "type": label,
                "masked": masked_val,
                "sha256": sha256_hex(orig.encode("utf-8", "ignore")),
            })
            stats[label] = stats.get(label, 0) + 1
            return masked_val

        masked = pattern.sub(repl, masked)

    return masked, hits, stats


def apply_mask_str(s: str, allowed_types: Optional[List[str]]) -> str:
    """문자열 하나에 대해 마스킹 적용"""
    return process_pii(s, allowed_types)[0]


# ──────────────────────────────
# 파일 단위 마스킹 로직
# ──────────────────────────────
def handle_masking(src_path: str, dst_masked_path: str, allowed_types: Optional[List[str]]) -> str:
    """
    dst_masked_path: 최종 마스킹 파일 경로 (저장될 곳)
    반환: 최종 마스킹된 파일 이름 (basename)
    """
    ext = os.path.splitext(src_path)[1].lower()
    os.makedirs(os.path.dirname(dst_masked_path), exist_ok=True)

    # TXT / CSV / JSON
    if ext in [".txt", ".csv", ".json"]:
        with open(src_path, "r", encoding="utf-8", errors="ignore") as f:
            masked = apply_mask_str(f.read(), allowed_types)
        with open(dst_masked_path, "w", encoding="utf-8") as f:
            f.write(masked)

    # XLSX
    elif ext == ".xlsx":
        wb = openpyxl.load_workbook(src_path, data_only=True)
        out = []
        for s in wb.sheetnames:
            for row in wb[s].iter_rows(values_only=True):
                out.append(" ".join(str(c) for c in row if c is not None))
        masked_txt = apply_mask_str("\n".join(out), allowed_types)
        base, _ = os.path.splitext(dst_masked_path)
        dst_masked_path = f"{base}_masked.txt"
        with open(dst_masked_path, "w", encoding="utf-8") as f:
            f.write(masked_txt)

    # PDF
    elif ext == ".pdf":
        text = []
        with pdfplumber.open(src_path) as pdf:
            for page in pdf.pages:
                text.append(page.extract_text() or "")
        masked_txt = apply_mask_str("\n".join(text), allowed_types)
        base, _ = os.path.splitext(dst_masked_path)
        dst_masked_path = f"{base}_masked.txt"
        with open(dst_masked_path, "w", encoding="utf-8") as f:
            f.write(masked_txt)

    # DOCX
    elif ext == ".docx":
        doc = DocxDocument(src_path)
        for p in doc.paragraphs:
            p.text = apply_mask_str(p.text, allowed_types)
        for table in doc.tables:
            for row in table.rows:
                for cell in row.cells:
                    for p in cell.paragraphs:
                        p.text = apply_mask_str(p.text, allowed_types)
        doc.save(dst_masked_path)

    # PPTX
    elif ext == ".pptx":
        prs = Presentation(src_path)
        for slide in prs.slides:
            for shape in slide.shapes:
                if hasattr(shape, "has_text_frame") and shape.has_text_frame:
                    for para in shape.text_frame.paragraphs:
                        para.text = apply_mask_str(para.text, allowed_types)
        prs.save(dst_masked_path)

    # 기타 포맷: 일반 텍스트로 처리
    else:
        with open(src_path, "r", encoding="utf-8", errors="ignore") as f:
            raw = f.read()
        masked = apply_mask_str(raw, allowed_types)
        base, _ = os.path.splitext(dst_masked_path)
        dst_masked_path = f"{base}_masked.txt"
        with open(dst_masked_path, "w", encoding="utf-8") as f:
            f.write(masked)

    return os.path.basename(dst_masked_path)


# ──────────────────────────────
# 마스킹 항목 정규화 유틸
# ──────────────────────────────
ALIASES = {
    "전화": "phone",
    "이메일": "email",
    "카드": "card_or_acct",
    "계좌": "card_or_acct",
    "인증": "auth",
    "주민등록번호": "rrn",
    "여권": "passport",
    "운전면허": "license",
    "외국인등록": "foreign_id",
    "주소": "address"
}

def _normalize_allowed_types(allowed_types: Optional[List[str] | str]) -> List[str]:
    """
    선택된 마스킹 항목을 정규화하여 유효한 리스트로 반환
    - 빈값(None, [])일 경우 ALWAYS_MASK만 반환
    - 콤마로 구분된 문자열도 허용
    """
    if not allowed_types:
        return list(ALWAYS_MASK)

    if isinstance(allowed_types, str):
        parts = [p.strip() for p in allowed_types.split(",") if p.strip()]
    else:
        parts = []
        for x in allowed_types:
            if x is None:
                continue
            s = str(x)
            if "," in s:
                parts.extend([p.strip() for p in s.split(",") if p.strip()])
            else:
                parts.append(s.strip())

    out = []
    for p in parts:
        k = ALIASES.get(p.lower(), p.lower())
        if k in VALID_KEYS:
            out.append(k)
    return list(set(out))

