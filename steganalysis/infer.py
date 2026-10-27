"""
infer.py
--------
High-performance inference engine for Gate 2 (Xu-Net Steganalysis).
Exposes simple programmatic interface for the FastAPI gateway middleware.
"""

import io
import os
from typing import Tuple, Union
import numpy as np
import torch
import torch.nn.functional as F
from PIL import Image
from torchvision import transforms

from .xunet import XuNet


class SteganalysisDetector:
    def __init__(
        self,
        weights_path: str = "steganalysis/model_weights/xunet_best.pth",
        threshold: float = 0.50,
        device: str = None,
    ):
        self.threshold = threshold
        self.weights_path = weights_path
        self.device = torch.device(
            device if device else ("cuda" if torch.cuda.is_available() else "cpu")
        )
        self.model = XuNet(in_channels=1, num_classes=2).to(self.device)
        self.is_loaded = False

        if os.path.exists(weights_path):
            try:
                checkpoint = torch.load(weights_path, map_location=self.device)
                if "model_state_dict" in checkpoint:
                    self.model.load_state_dict(checkpoint["model_state_dict"])
                else:
                    self.model.load_state_dict(checkpoint)
                self.is_loaded = True
                print(f"[+] Loaded Xu-Net weights from {weights_path}")
            except Exception as e:
                print(f"[!] Warning: Could not load weights from {weights_path}: {e}")
        else:
            print(f"[*] Xu-Net weights file not found at {weights_path}. Running with initialized architecture.")

        self.model.eval()

        self.transform = transforms.Compose([
            transforms.Resize((256, 256)),
            transforms.ToTensor(),
            transforms.Normalize(mean=[0.5], std=[0.5]),
        ])

    def predict_image(
        self,
        image_input: Union[str, bytes, Image.Image],
    ) -> Tuple[bool, float, dict]:
        """
        Runs steganalysis on image.
        Returns:
          - is_stego: bool (True if suspected steganographic payload detected)
          - stego_prob: float (0.0 to 1.0 confidence score)
          - details: dict (diagnostic information)
        """
        if isinstance(image_input, str):
            img = Image.open(image_input).convert("L")
        elif isinstance(image_input, bytes):
            img = Image.open(io.BytesIO(image_input)).convert("L")
        elif isinstance(image_input, Image.Image):
            img = image_input.convert("L")
        else:
            raise ValueError("Unsupported image input type.")

        tensor = self.transform(img).unsqueeze(0).to(self.device)

        with torch.no_grad():
            logits = self.model(tensor)
            probs = F.softmax(logits, dim=1)
            stego_prob = float(probs[0, 1].item())
            clean_prob = float(probs[0, 0].item())

        is_stego = stego_prob >= self.threshold

        details = {
            "stego_probability": round(stego_prob, 4),
            "clean_probability": round(clean_prob, 4),
            "threshold": self.threshold,
            "weights_loaded": self.is_loaded,
            "verdict": "STEGO_SUSPECTED" if is_stego else "CLEAN",
        }

        return is_stego, stego_prob, details
