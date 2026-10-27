"""
verify.py
---------
Runs at the GATEWAY. This IS Gate 1 of the dual-gate architecture.

Given an image and its cryptographic manifest, re-hashes the image bytes
and checks the ECDSA signature against the source's PUBLIC key.

Three possible outcomes:
    - VALID            -> signature verified, image passes straight through (skips Gate 2)
    - UNSIGNED         -> no manifest found at all, route to Gate 2
    - INVALID_SIGNATURE -> manifest present but doesn't verify
                           (tampered image, forged signature, or wrong key),
                           route to Gate 2
"""

import argparse
import base64
import json
import os
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .sign import hash_image, hash_bytes


class VerificationResult(str, Enum):
    VALID = "valid"
    UNSIGNED = "unsigned"
    INVALID_SIGNATURE = "invalid_signature"


@dataclass
class GateDecision:
    result: VerificationResult
    source_id: Optional[str]
    route_to_gate_2: bool
    reason: str
    sha256: str


def load_public_key(public_key_path: str):
    with open(public_key_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_public_key_from_bytes(key_bytes: bytes):
    return serialization.load_pem_public_key(key_bytes)


def load_manifest(image_path: str) -> Optional[dict]:
    manifest_path = f"{image_path}.sig.json"
    if not os.path.exists(manifest_path):
        return None
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def verify_image(image_path: str, public_key_path: str) -> GateDecision:
    """Verifies image file on disk against its sidecar manifest (.sig.json)."""
    manifest = load_manifest(image_path)
    current_digest = hash_image(image_path)
    sha256_hex = current_digest.hex()

    if manifest is None:
        return GateDecision(
            result=VerificationResult.UNSIGNED,
            source_id=None,
            route_to_gate_2=True,
            reason="No signature manifest found alongside the image (Unverified Origin).",
            sha256=sha256_hex,
        )

    return _verify_manifest_and_digest(manifest, current_digest, public_key_path, sha256_hex)


def verify_image_bytes(
    image_bytes: bytes,
    manifest_dict: Optional[dict],
    public_key_path: str,
) -> GateDecision:
    """Verifies image in-memory bytes and supplied manifest dict."""
    current_digest = hash_bytes(image_bytes)
    sha256_hex = current_digest.hex()

    if manifest_dict is None:
        return GateDecision(
            result=VerificationResult.UNSIGNED,
            source_id=None,
            route_to_gate_2=True,
            reason="Image upload does not include cryptographic provenance manifest.",
            sha256=sha256_hex,
        )

    return _verify_manifest_and_digest(manifest_dict, current_digest, public_key_path, sha256_hex)


def _verify_manifest_and_digest(
    manifest: dict,
    current_digest: bytes,
    public_key_path: str,
    sha256_hex: str,
) -> GateDecision:
    try:
        claimed_digest = bytes.fromhex(manifest["hash_sha256"])
        signature = base64.b64decode(manifest["signature_b64"])
    except Exception as e:
        return GateDecision(
            result=VerificationResult.INVALID_SIGNATURE,
            source_id=manifest.get("source_id"),
            route_to_gate_2=True,
            reason=f"Corrupt or malformed manifest: {str(e)}",
            sha256=sha256_hex,
        )

    hash_changed = current_digest != claimed_digest

    try:
        public_key = load_public_key(public_key_path)
        public_key.verify(signature, current_digest, ec.ECDSA(hashes.SHA256()))

        if hash_changed:
            return GateDecision(
                result=VerificationResult.INVALID_SIGNATURE,
                source_id=manifest.get("source_id"),
                route_to_gate_2=True,
                reason="Signature validates against current bytes but hash in manifest diverges. Tamper alert.",
                sha256=sha256_hex,
            )

        return GateDecision(
            result=VerificationResult.VALID,
            source_id=manifest.get("source_id"),
            route_to_gate_2=False,
            reason=f"ECDSA P-256 signature verified. Trusted source: '{manifest.get('source_id')}'.",
            sha256=sha256_hex,
        )
    except InvalidSignature:
        return GateDecision(
            result=VerificationResult.INVALID_SIGNATURE,
            source_id=manifest.get("source_id"),
            route_to_gate_2=True,
            reason="ECDSA signature mismatch: image was modified post-signing or forged with invalid key.",
            sha256=sha256_hex,
        )
    except Exception as e:
        return GateDecision(
            result=VerificationResult.INVALID_SIGNATURE,
            source_id=manifest.get("source_id"),
            route_to_gate_2=True,
            reason=f"Verification failure: {str(e)}",
            sha256=sha256_hex,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify an image's ECDSA signature (Gate 1).")
    parser.add_argument("--image", required=True, help="Path to the image file to verify.")
    parser.add_argument("--public-key", required=True, help="Path to the source's PEM public key.")
    args = parser.parse_args()

    decision = verify_image(args.image, args.public_key)
    print(f"Result:         {decision.result.value}")
    print(f"Source:         {decision.source_id}")
    print(f"Route to Gate 2: {decision.route_to_gate_2}")
    print(f"Reason:         {decision.reason}")
