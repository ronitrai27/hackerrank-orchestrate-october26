"""Multimodal OCR and Document Extraction Cache using Gemini 2.5 Flash and pdfplumber.

Processes the 11 PNG screenshots and 4 PDFs in dataset/evidence/ and caches
the structured extracted text so OCR runs exactly once and is instantly available.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional
import pdfplumber
from PIL import Image
from google import genai

from code.src.config.settings import settings

CACHE_DIR = settings.repo_root / ".cache" / "ocr"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
CACHE_FILE = CACHE_DIR / "evidence_ocr_cache.json"


class OCRExtractor:
    """Extracts and caches text and tables from images and PDF documents."""

    def __init__(self):
        self.client: Optional[genai.Client] = None
        if settings.has_google:
            self.client = genai.Client(api_key=settings.google_api_key)
        self._cache: Dict[str, str] = self._load_cache()

    def _load_cache(self) -> Dict[str, str]:
        if CACHE_FILE.exists():
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_cache(self) -> None:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(self._cache, f, indent=2, ensure_ascii=False)

    def extract_pdf(self, pdf_path: Path) -> str:
        """Extract text from PDF using pdfplumber."""
        rel_key = str(pdf_path.relative_to(settings.repo_root)) if pdf_path.is_relative_to(settings.repo_root) else pdf_path.name
        if rel_key in self._cache:
            return self._cache[rel_key]

        text_parts = []
        try:
            with pdfplumber.open(pdf_path) as pdf:
                for page in pdf.pages:
                    page_text = page.extract_text()
                    if page_text:
                        text_parts.append(page_text)
            extracted = "\n".join(text_parts).strip()
            self._cache[rel_key] = extracted
            self._save_cache()
            return extracted
        except Exception as e:
            return f"[PDF_EXTRACTION_ERROR: {e}]"

    def extract_image(self, img_path: Path) -> str:
        """Extract UI dashboard content and text from image using Gemini 2.5 Flash."""
        rel_key = str(img_path.relative_to(settings.repo_root)) if img_path.is_relative_to(settings.repo_root) else img_path.name
        if rel_key in self._cache:
            return self._cache[rel_key]

        if not self.client:
            return "[IMAGE_OCR_UNAVAILABLE_NO_GOOGLE_KEY]"

        prompt = (
            "Analyze this application/dashboard screenshot carefully. "
            "Extract all tables, rows, customer IDs (user_id), resource IDs (e.g. account_xxx, search_xxx, support_xxx), "
            "emails, full names, phone numbers, timestamps, and status values (ACTIVE, DELETED, REDACTED, etc.). "
            "Output clear, structured text representing all data shown."
        )

        try:
            pil_img = Image.open(img_path)
            response = self.client.models.generate_content(
                model=settings.gemini_model,
                contents=[prompt, pil_img],
            )
            extracted = response.text.strip() if response.text else ""
            self._cache[rel_key] = extracted
            self._save_cache()
            return extracted
        except Exception as e:
            return f"[IMAGE_OCR_ERROR: {e}]"

    def extract_evidence_file(self, rel_path: str) -> str:
        """Extract evidence file content if it is an image or PDF, otherwise return empty string."""
        abs_path = settings.dataset_dir / rel_path
        if not abs_path.exists():
            return ""

        suffix = abs_path.suffix.lower()
        if suffix in [".png", ".jpg", ".jpeg"]:
            return self.extract_image(abs_path)
        elif suffix == ".pdf":
            return self.extract_pdf(abs_path)
        return ""


# Singleton instance
ocr_extractor = OCRExtractor()
