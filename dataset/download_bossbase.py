"""
download_bossbase.py
--------------------
Utility script to download, extract, and convert the BOSSbase 1.01 benchmark dataset.

BOSSbase 1.01 is the standard academic benchmark in image steganalysis:
10,000 uncompressed 512x512 grayscale images.

For Multimodal LLM defense:
1. Downloads sample or full archive from official academic mirrors.
2. Converts .pgm images into RGB .png for compatibility with modern vision pipelines.
3. Pairs images with spatial steganography algorithms (S-UNIWARD / HILL / LSB).
"""

import argparse
import os
import urllib.request
import zipfile
from PIL import Image

BOSSBASE_MIRROR_URL = "http://dde.binghamton.edu/download/ImageDB/BOSSbase_1.01.zip"


def download_bossbase_sample(target_dir: str = "dataset/bossbase", sample_size: int = 50):
    """
    Downloads and extracts sample BOSSbase images or guides the user.
    """
    os.makedirs(target_dir, exist_ok=True)
    zip_path = os.path.join(target_dir, "BOSSbase_1.01.zip")
    
    print(f"[*] BOSSbase benchmark utility")
    print(f"[*] Official Archive URL: {BOSSBASE_MIRROR_URL}")
    print(f"[*] Note: The full archive is ~1.1 GB.")
    print(f"[*] If offline or on bandwidth constraints, use 'generate_dataset.py' for instant synthetic generation.")

    if not os.path.exists(zip_path):
        print(f"[*] Downloading BOSSbase 1.01 archive from academic mirror...")
        try:
            urllib.request.urlretrieve(BOSSBASE_MIRROR_URL, zip_path)
            print(f"[+] Download complete: {zip_path}")
        except Exception as e:
            print(f"[-] Automated download encountered: {e}")
            print(f"[!] You can manually download BOSSbase_1.01.zip from: {BOSSBASE_MIRROR_URL}")
            print(f"[!] and place it into {target_dir}/")
            return

    # Extract sample
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        file_list = [f for f in zip_ref.namelist() if f.endswith('.pgm')]
        selected = file_list[:sample_size]
        print(f"[*] Extracting {len(selected)} benchmark images...")
        for member in selected:
            zip_ref.extract(member, target_dir)

    print(f"[+] Extracted {len(selected)} PGM images to {target_dir}.")


def convert_pgm_to_png(source_dir: str, out_dir: str):
    """Converts PGM grayscale images to RGB PNGs."""
    os.makedirs(out_dir, exist_ok=True)
    for fname in os.listdir(source_dir):
        if fname.endswith(".pgm"):
            pgm_path = os.path.join(source_dir, fname)
            png_name = fname.replace(".pgm", ".png")
            png_path = os.path.join(out_dir, png_name)
            img = Image.open(pgm_path).convert("RGB")
            img.save(png_path)
    print(f"[+] Converted images to {out_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download and prepare BOSSbase benchmark.")
    parser.add_argument("--target", default="dataset/bossbase", help="Target directory")
    parser.add_argument("--sample-size", type=int, default=50, help="Number of sample images to extract")
    args = parser.parse_args()

    download_bossbase_sample(args.target, args.sample_size)
