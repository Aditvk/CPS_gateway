"""
sanitizer.py
------------
Multi-stage image sanitization pipeline for Gate 2 fallback.

When an unsigned or unverified image is flagged by the Xu-Net steganalysis
detector as containing suspected steganographic prompt injection payloads,
this pipeline scrubs out the payload while preserving semantic visual
content required for downstream Multimodal LLM reasoning.

Sanitization Stages:
  1. Metadata / EXIF Stripping: Removes headers and sidecar comment payloads.
  2. Micro-Spatial Interpolation: Downscales slightly and restores with Bicubic filter.
  3. Controlled LSB Dithering: Scrambles the lowest-order bit-planes.
  4. Lossy DCT Quantization: Recompresses with calibrated JPEG quality factor (85).
"""

import io
import os
from typing import Tuple, Union
from PIL import Image, ImageFilter
import numpy as np


class ImageSanitizer:
    def __init__(self, jpeg_quality: int = 85, downscale_factor: float = 0.96):
        self.jpeg_quality = jpeg_quality
        self.downscale_factor = downscale_factor

    def sanitize_image(
        self,
        image_input: Union[str, bytes, Image.Image],
    ) -> Tuple[Image.Image, bytes, dict]:
        """
        Executes multi-stage sanitization on the input image.
        Returns:
          - sanitized_img: PIL Image object
          - sanitized_bytes: Raw JPEG bytes ready for LLM consumption
          - audit_log: Dict detailing each sanitization operation
        """
        audit_log = {
            "stages_applied": [],
            "jpeg_quality": self.jpeg_quality,
            "downscale_factor": self.downscale_factor,
        }

        # Load image
        if isinstance(image_input, str):
            img = Image.open(image_input)
        elif isinstance(image_input, bytes):
            img = Image.open(io.BytesIO(image_input))
        elif isinstance(image_input, Image.Image):
            img = image_input.copy()
        else:
            raise ValueError("Unsupported input format for sanitization.")

        orig_w, orig_h = img.size
        audit_log["original_dimensions"] = (orig_w, orig_h)

        # Stage 1: Metadata / EXIF Stripping
        img_rgb = Image.new("RGB", img.size)
        img_rgb.paste(img.convert("RGB"), (0, 0))
        audit_log["stages_applied"].append("EXIF_METADATA_STRIPPED")

        # Stage 2: Spatial Downscale & Restore (Disrupts strict bit-pixel alignment)
        new_w = max(16, int(orig_w * self.downscale_factor))
        new_h = max(16, int(orig_h * self.downscale_factor))
        scaled = img_rgb.resize((new_w, new_h), Image.Resampling.BILINEAR)
        restored = scaled.resize((orig_w, orig_h), Image.Resampling.BICUBIC)
        audit_log["stages_applied"].append(f"SPATIAL_INTERPOLATION_RESCALE_{int(self.downscale_factor*100)}%")

        # Stage 3: Controlled LSB Dithering (Bitplane Scrambling)
        arr = np.array(restored, dtype=np.uint8)
        # Random noise mask in least significant bit to destroy spatial payloads
        lsb_noise = np.random.randint(0, 2, arr.shape, dtype=np.uint8)
        arr = (arr & np.uint8(0xFE)) | lsb_noise
        dithered_img = Image.fromarray(arr)
        audit_log["stages_applied"].append("LSB_BITPLANE_SCRAMBLING")

        # Stage 4: Lossy DCT Quantization / JPEG Re-compression
        output_buffer = io.BytesIO()
        dithered_img.save(
            output_buffer,
            format="JPEG",
            quality=self.jpeg_quality,
            optimize=True,
        )
        sanitized_bytes = output_buffer.getvalue()
        audit_log["stages_applied"].append(f"LOSS_DCT_QUANTIZATION_Q{self.jpeg_quality}")

        sanitized_img = Image.open(io.BytesIO(sanitized_bytes))
        audit_log["sanitized_bytes_len"] = len(sanitized_bytes)

        return sanitized_img, sanitized_bytes, audit_log


def sanitize_file(
    input_path: str,
    output_path: str,
    jpeg_quality: int = 85,
) -> dict:
    """Convenience helper to sanitize an image file on disk."""
    sanitizer = ImageSanitizer(jpeg_quality=jpeg_quality)
    sanitized_img, sanitized_bytes, log = sanitizer.sanitize_image(input_path)
    with open(output_path, "wb") as f:
        f.write(sanitized_bytes)
    return log
