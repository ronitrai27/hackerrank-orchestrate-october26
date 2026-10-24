"""Centralized configuration and environment loader.

Loads API keys and paths from .env in a production-safe, structured manner.
No secrets are logged or exposed.
"""

import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Locate repository root and dataset directories
# Current file is in code/src/config/settings.py -> 3 levels up is repo root
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DATASET_DIR = REPO_ROOT / "dataset"
OUTPUT_CSV_PATH = REPO_ROOT / "output.csv"

# Ensure repository root is in sys.path
import sys
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Load .env from repository root if present
ENV_PATH = REPO_ROOT / ".env"
if ENV_PATH.exists():
    load_dotenv(dotenv_path=ENV_PATH)


class Settings(BaseModel):
    """Application and Model settings loaded from environment."""

    # Models
    gpt_model: str = Field(default="gpt-4.1-mini", description="Synthesis & generation model")
    jev_model: str = Field(default="typesafe/jev-1.14", description="TypeSafe JEV decision model")
    gemini_model: str = Field(default="gemini-2.5-flash", description="Gemini multimodal & OCR model")

    # API Keys & Endpoints
    google_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
    )
    openai_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("OPENAI_API_KEY")
    )
    openai_base_url: Optional[str] = Field(
        default_factory=lambda: os.getenv("OPENAI_BASE_URL")
    )
    typesafe_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("TYPESAFE_API_KEY") or os.getenv("JEV_API_KEY")
    )
    typesafe_base_url: Optional[str] = Field(
        default_factory=lambda: os.getenv("TYPESAFE_BASE_URL")
    )

    # Langfuse Observability (Optional)
    langfuse_public_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("LANGFUSE_PUBLIC_KEY")
    )
    langfuse_secret_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("LANGFUSE_SECRET_KEY")
    )
    langfuse_host: Optional[str] = Field(
        default_factory=lambda: os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com")
    )

    # File Paths
    repo_root: Path = REPO_ROOT
    dataset_dir: Path = DATASET_DIR
    output_csv_path: Path = OUTPUT_CSV_PATH

    @property
    def has_google(self) -> bool:
        return bool(self.google_api_key)

    @property
    def has_openai(self) -> bool:
        return bool(self.openai_api_key)

    @property
    def has_typesafe(self) -> bool:
        return bool(self.typesafe_api_key)


# Global singleton settings instance
settings = Settings()
