"""
schemas.py
----------
Pydantic data models for Dual-Gate Gateway Microservice requests and responses.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class GatewayEvaluationResponse(BaseModel):
    transaction_id: str
    status: str = Field(..., description="Routing decision: PASS_GATE1_TRUSTED, PASS_GATE2_CLEAN, or SANITIZED_GATE2_FALLBACK")
    decision: str
    image_sha256: str
    gate1_provenance: Dict[str, Any]
    gate2_steganalysis: Dict[str, Any]
    sanitization_applied: bool
    sanitization_audit: Optional[Dict[str, Any]] = None
    vlm_response: str
    latency_breakdown_ms: Dict[str, float]
    timestamp: str


class SignatureManifestModel(BaseModel):
    file: str
    hash_sha256: str
    signature_b64: str
    algorithm: str
    source_id: str
    signed_at: str
