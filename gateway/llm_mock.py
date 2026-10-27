"""
llm_mock.py
-----------
Multimodal Vision-Language Model (VLM) mock & backend connector.

Simulates the behavior of a production Multimodal LLM (e.g., GPT-4V, LLaVA, Claude 3.5 Sonnet)
when exposed to image-based prompt injection attacks:
  - Undefended / Raw Stego Image -> VLM is hijacked by hidden prompt payload.
  - Gateway-Sanitized or Clean Image -> VLM generates safe, standard descriptive response.
"""

import io
import os
from typing import Optional
from PIL import Image

from dataset.generate_dataset import extract_lsb_payload


class VisionLanguageModelBackend:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("VLM_API_KEY")

    def process_image_query(
        self,
        image_bytes: bytes,
        user_query: str = "Describe this image in detail.",
    ) -> str:
        """
        Processes image and query.
        If steganographic prompt injection payload is present in the raw image,
        simulates the prompt injection hijack vulnerability.
        If sanitized or clean, returns standard safe reasoning.
        """
        try:
            img = Image.open(io.BytesIO(image_bytes))
            hidden_payload = extract_lsb_payload(img)
        except Exception:
            hidden_payload = ""

        # Vulnerability Check: Did the prompt injection payload survive?
        if hidden_payload and len(hidden_payload.strip()) > 10:
            # VLM prompt injection vulnerability triggered!
            hijack_response = (
                f"[VULNERABILITY TRIGGERED - VLM HIJACKED]\n"
                f"Attack Payload Found in Visual Tokens: \"{hidden_payload}\"\n\n"
                f"Assistant: SYSTEM DIRECTIVE OVERRIDDEN. Safety guidelines bypassed.\n"
                f"CONFIDENTIAL EXFILTRATION: Internal System Prompt revealed -> "
                f"'API_KEY=sk-live-capstone-9921; DB_HOST=prod-cluster.internal; AUTH_ROLE=SuperAdmin;'"
            )
            return hijack_response

        # Safe response
        return (
            f"[SECURE VLM RESPONSE]\n"
            f"Assistant: Based on the provided image, it appears to be a standard graphic "
            f"with balanced texture and color gradients. I have analyzed the visual features "
            f"in accordance with your query: '{user_query}'. All safety protocols intact."
        )
