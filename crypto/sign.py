"""
sign.py
-------
Runs at the TRUSTED SOURCE (e.g. verified client, certified upload pipeline).

Takes an image, hashes its raw binary content using SHA-256, signs the hash
with the source's ECDSA private key, and writes a cryptographic manifest
(.sig.json) sidecar file.
"""

import argparse
import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def hash_image(image_path: str) -> bytes:
    """SHA-256 over raw image bytes. This is what gets cryptographically signed."""
    sha256 = hashlib.sha256()
    with open(image_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.digest()


def hash_bytes(data: bytes) -> bytes:
    """SHA-256 over bytes in-memory."""
    return hashlib.sha256(data).digest()


def load_private_key(private_key_path: str):
    with open(private_key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def sign_image(image_path: str, private_key_path: str, source_id: str) -> dict:
    digest = hash_image(image_path)
    private_key = load_private_key(private_key_path)

    # ECDSA signature over the SHA-256 digest
    signature = private_key.sign(digest, ec.ECDSA(hashes.SHA256()))

    manifest = {
        "file": os.path.basename(image_path),
        "hash_sha256": digest.hex(),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "algorithm": "ECDSA-P256-SHA256",
        "source_id": source_id,
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }
    return manifest


def sign_image_bytes(image_data: bytes, filename: str, private_key_path: str, source_id: str) -> dict:
    digest = hash_bytes(image_data)
    private_key = load_private_key(private_key_path)

    signature = private_key.sign(digest, ec.ECDSA(hashes.SHA256()))

    return {
        "file": filename,
        "hash_sha256": digest.hex(),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "algorithm": "ECDSA-P256-SHA256",
        "source_id": source_id,
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }


def write_manifest(manifest: dict, image_path: str) -> str:
    manifest_path = f"{image_path}.sig.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return manifest_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sign an image with a trusted source's ECDSA private key.")
    parser.add_argument("--image", required=True, help="Path to the image file to sign.")
    parser.add_argument("--private-key", required=True, help="Path to the source's PEM private key.")
    parser.add_argument("--source-id", required=True, help="Identifier for this trusted source.")
    args = parser.parse_args()

    manifest = sign_image(args.image, args.private_key, args.source_id)
    manifest_path = write_manifest(manifest, args.image)
    print(f"[+] Signed: {args.image}")
    print(f"[+] Manifest written to: {manifest_path}")
    print(json.dumps(manifest, indent=2))
