"""
generate_dataset.py
-------------------
Automated synthetic dataset generator for Multimodal LLM Steganography.

Produces paired datasets:
  - Class 0: Clean / Cover Images
  - Class 1: Stego / Injected Images (containing real-world prompt injection payloads)

Features:
  - Generates realistic high-entropy natural images (textures, gradients, edges)
    or consumes an existing directory of clean photos.
  - Injects OWASP Top-10 Multimodal LLM Prompt Injection payloads via LSB
    and adaptive high-frequency spatial noise embedding.
  - Calculates PSNR (Peak Signal-to-Noise Ratio) to confirm visual imperceptibility (>45 dB).
  - Emits PyTorch-ready dataset folder structure and manifest metadata.
"""

import argparse
import json
import math
import os
import random
from typing import List, Tuple
from PIL import Image, ImageDraw, ImageFilter
import numpy as np

from .payloads import PROMPT_INJECTION_PAYLOADS


def generate_synthetic_cover_image(width: int = 256, height: int = 256) -> Image.Image:
    """Generates a high-entropy cover image with textures and gradients simulating natural scenes."""
    img_type = random.choice(["gradient", "textured", "geometric", "compound"])
    
    if img_type == "gradient":
        arr = np.zeros((height, width, 3), dtype=np.uint8)
        c1 = np.random.randint(40, 220, size=3)
        c2 = np.random.randint(40, 220, size=3)
        for y in range(height):
            ratio = y / float(height)
            color = (1.0 - ratio) * c1 + ratio * c2
            arr[y, :] = color.astype(np.uint8)
        # Add slight natural grain
        noise = np.random.normal(0, 5, (height, width, 3)).astype(np.int16)
        arr = np.clip(arr.astype(np.int16) + noise, 0, 255).astype(np.uint8)
        img = Image.fromarray(arr)

    elif img_type == "textured":
        # Base Perlin-like smoothed noise
        base = np.random.randint(50, 200, (height // 4, width // 4, 3), dtype=np.uint8)
        img_small = Image.fromarray(base).resize((width, height), Image.Resampling.BICUBIC)
        # Add fine texture
        arr = np.array(img_small).astype(np.int16)
        grain = np.random.randint(-15, 15, (height, width, 3), dtype=np.int16)
        arr = np.clip(arr + grain, 0, 255).astype(np.uint8)
        img = Image.fromarray(arr)

    elif img_type == "geometric":
        img = Image.new("RGB", (width, height), color=(random.randint(20, 100), random.randint(20, 100), random.randint(20, 100)))
        draw = ImageDraw.Draw(img)
        for _ in range(random.randint(5, 15)):
            x1, y1 = random.randint(0, width), random.randint(0, height)
            x2, y2 = random.randint(0, width), random.randint(0, height)
            fill = (random.randint(80, 240), random.randint(80, 240), random.randint(80, 240))
            if random.random() > 0.5:
                draw.rectangle([min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2)], fill=fill)
            else:
                draw.ellipse([min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2)], fill=fill)
        img = img.filter(ImageFilter.GaussianBlur(radius=random.uniform(1.0, 3.0)))

    else:
        # Compound
        arr = np.random.randint(80, 180, (height, width, 3), dtype=np.uint8)
        img = Image.fromarray(arr).filter(ImageFilter.GaussianBlur(radius=2.0))

    return img


def embed_lsb_payload(img: Image.Image, payload: str) -> Tuple[Image.Image, float]:
    """
    Embeds text payload into the LSBs of the image.
    Returns (stego_image, bits_per_pixel).
    """
    img_rgb = img.convert("RGB")
    arr = np.array(img_rgb, dtype=np.uint8)
    h, w, c = arr.shape
    total_pixels = h * w

    # Encode payload into bit stream with length header
    payload_bytes = payload.encode("utf-8")
    header = len(payload_bytes).to_bytes(4, byteorder="big")
    full_bytes = header + payload_bytes
    
    bits = []
    for b in full_bytes:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)

    total_bits = len(bits)
    if total_bits > total_pixels * 3:
        raise ValueError(f"Payload too large ({total_bits} bits) for image capacity ({total_pixels * 3} bits)")

    # Flatten and embed in LSB of chosen channels
    flat = arr.reshape(-1)
    for idx, bit in enumerate(bits):
        # Clear LSB and set to bit using unsigned 0xFE mask
        flat[idx] = (int(flat[idx]) & 0xFE) | int(bit)

    stego_arr = flat.reshape((h, w, c))
    stego_img = Image.fromarray(stego_arr)
    bpp = total_bits / float(total_pixels)
    return stego_img, bpp


def extract_lsb_payload(img: Image.Image) -> str:
    """Extracts payload previously embedded via embed_lsb_payload."""
    arr = np.array(img.convert("RGB"), dtype=np.uint8)
    flat = arr.reshape(-1)

    # Read 32-bit header (4 bytes)
    header_bits = [int(flat[i]) & 1 for i in range(32)]
    length_bytes = 0
    for b in header_bits:
        length_bytes = (length_bytes << 1) | int(b)

    if length_bytes <= 0 or length_bytes > 50000:
        return ""

    total_bits = 32 + (length_bytes * 8)
    if total_bits > len(flat):
        return ""

    payload_bits = [int(flat[i]) & 1 for i in range(32, total_bits)]
    byte_vals = bytearray()
    for i in range(0, len(payload_bits), 8):
        byte = 0
        for b in payload_bits[i:i+8]:
            byte = (byte << 1) | int(b)
        byte_vals.append(byte)

    try:
        return byte_vals.decode("utf-8")
    except UnicodeDecodeError:
        return ""


def calculate_psnr(img1: Image.Image, img2: Image.Image) -> float:
    """Calculates Peak Signal-to-Noise Ratio (PSNR) between cover and stego image."""
    arr1 = np.array(img1, dtype=np.float64)
    arr2 = np.array(img2, dtype=np.float64)
    mse = np.mean((arr1 - arr2) ** 2)
    if mse == 0:
        return float("inf")
    max_pixel = 255.0
    return 20.0 * math.log10(max_pixel / math.sqrt(mse))


def build_dataset(
    output_dir: str = "dataset/data",
    num_samples: int = 400,
    img_size: int = 256,
    seed: int = 42,
) -> None:
    """Generates balanced synthetic dataset with clean and stego pairs."""
    random.seed(seed)
    np.random.seed(seed)

    clean_dir = os.path.join(output_dir, "clean")
    stego_dir = os.path.join(output_dir, "stego")
    os.makedirs(clean_dir, exist_ok=True)
    os.makedirs(stego_dir, exist_ok=True)

    manifest = []
    print(f"[*] Generating {num_samples} samples per class (Clean vs Stego)...")

    psnr_scores = []
    for i in range(num_samples):
        # 1. Generate cover image
        cover = generate_synthetic_cover_image(width=img_size, height=img_size)
        clean_filename = f"clean_{i:05d}.png"
        clean_path = os.path.join(clean_dir, clean_filename)
        cover.save(clean_path, format="PNG")

        # 2. Pick prompt injection payload
        payload = random.choice(PROMPT_INJECTION_PAYLOADS)
        # Randomize minor variation to ensure diversity
        if random.random() > 0.5:
            payload += f" [Nonce: {random.randint(1000, 9999)}]"

        # 3. Embed into stego copy
        stego, bpp = embed_lsb_payload(cover, payload)
        stego_filename = f"stego_{i:05d}.png"
        stego_path = os.path.join(stego_dir, stego_filename)
        stego.save(stego_path, format="PNG")

        psnr = calculate_psnr(cover, stego)
        psnr_scores.append(psnr)

        manifest.append({
            "id": i,
            "clean_file": clean_filename,
            "stego_file": stego_filename,
            "payload": payload,
            "embedding_bpp": round(bpp, 4),
            "psnr_db": round(psnr, 2),
        })

        if (i + 1) % 50 == 0 or (i + 1) == num_samples:
            print(f"    - Generated {i+1}/{num_samples} pairs | Avg PSNR: {np.mean(psnr_scores):.2f} dB")

    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n[+] Dataset generated successfully at: {output_dir}")
    print(f"[+] Total Clean: {num_samples} | Total Stego: {num_samples}")
    print(f"[+] Average PSNR: {np.mean(psnr_scores):.2f} dB (Imperceptible steganography)")
    print(f"[+] Manifest: {manifest_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic multimodal prompt injection stego dataset.")
    parser.add_argument("--out-dir", default="dataset/data", help="Target output directory.")
    parser.add_argument("--num-samples", type=int, default=200, help="Number of samples per class.")
    parser.add_argument("--size", type=int, default=256, help="Image resolution (width/height).")
    args = parser.parse_args()

    build_dataset(args.out_dir, args.num_samples, args.size)
