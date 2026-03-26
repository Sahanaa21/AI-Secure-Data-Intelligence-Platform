"""
File Parser Module
Extracts text content from PDF, DOCX, TXT, LOG, and SQL files.
"""

import io
from typing import Optional


def extract_text_from_file(filename: str, file_bytes: bytes) -> str:
    """
    Extract plain text from various file types.
    
    Supports: .pdf, .docx, .doc, .txt, .log, .sql, .csv
    Falls back to raw UTF-8 decode for unknown types.
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if ext == "pdf":
        return _parse_pdf(file_bytes)
    elif ext in ("docx", "doc"):
        return _parse_docx(file_bytes)
    elif ext in ("txt", "log", "sql", "csv", "json", "xml", "yaml", "yml", "env", "conf", "config"):
        return _parse_text(file_bytes)
    else:
        return _parse_text(file_bytes)


def _parse_pdf(data: bytes) -> str:
    try:
        import pdfplumber
        with pdfplumber.open(io.BytesIO(data)) as pdf:
            texts = []
            for page in pdf.pages:
                text = page.extract_text()
                if text:
                    texts.append(text)
            return "\n".join(texts)
    except ImportError:
        return "[PDF parsing unavailable — install pdfplumber]"
    except Exception as e:
        return f"[PDF parsing error: {e}]"


def _parse_docx(data: bytes) -> str:
    try:
        from docx import Document
        doc = Document(io.BytesIO(data))
        paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
        return "\n".join(paragraphs)
    except ImportError:
        return "[DOCX parsing unavailable — install python-docx]"
    except Exception as e:
        return f"[DOCX parsing error: {e}]"


def _parse_text(data: bytes) -> str:
    """Attempt UTF-8 decode, then latin-1 fallback."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("latin-1")
        except Exception:
            return data.decode("utf-8", errors="replace")
