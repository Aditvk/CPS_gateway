"""
Dataset generation and benchmark handling.
"""

from .payloads import PROMPT_INJECTION_PAYLOADS
from .generate_dataset import (
    generate_synthetic_cover_image,
    embed_lsb_payload,
    extract_lsb_payload,
    calculate_psnr,
    build_dataset,
)

__all__ = [
    "PROMPT_INJECTION_PAYLOADS",
    "generate_synthetic_cover_image",
    "embed_lsb_payload",
    "extract_lsb_payload",
    "calculate_psnr",
    "build_dataset",
]
