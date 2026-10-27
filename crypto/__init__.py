"""
Cryptographic Provenance Module (Gate 1)
Dual-Gate Multimodal LLM Security Gateway
"""

from .generate_keys import generate_key_pair
from .sign import sign_image, write_manifest, hash_image
from .verify import verify_image, VerificationResult, GateDecision

__all__ = [
    "generate_key_pair",
    "sign_image",
    "write_manifest",
    "hash_image",
    "verify_image",
    "VerificationResult",
    "GateDecision",
]
