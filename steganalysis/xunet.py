"""
xunet.py
--------
Xu-Net Deep Learning Architecture for Spatial Steganalysis.

Reference:
  G. Xu, H. Z. Wu and Y. Q. Shi, "Structural Design of Convolutional Neural Networks
  for Steganalysis," IEEE Signal Processing Letters, vol. 23, no. 5, pp. 708-712, 2016.

Key Innovations:
  1. Fixed 5x5 High-Pass Preprocessing Filter (KV Filter) to suppress content
     and extract high-frequency steganographic noise residuals.
  2. Absolute value activation layer (ABS) in the initial stage.
  3. Batch normalization and average pooling across all convolutional blocks.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np


class ABS(nn.Module):
    """Absolute Value Activation Layer."""
    def forward(self, x):
        return torch.abs(x)


class XuNet(nn.Module):
    def __init__(self, in_channels: int = 1, num_classes: int = 2):
        """
        Xu-Net classifier.
        in_channels: 1 for grayscale or 3 for RGB (processed across channels).
        num_classes: 2 (0: Clean, 1: Stego/Injected)
        """
        super(XuNet, self).__init__()

        # 5x5 High-Pass KV Filter kernel
        kv_kernel = np.array([
            [-1,  2,  -2,  2, -1],
            [ 2, -6,   8, -6,  2],
            [-2,  8, -12,  8, -2],
            [ 2, -6,   8, -6,  2],
            [-1,  2,  -2,  2, -1]
        ], dtype=np.float32) / 12.0

        # Create preprocessing conv layer with fixed weights
        self.kv_conv = nn.Conv2d(in_channels, in_channels, kernel_size=5, stride=1, padding=2, bias=False)
        with torch.no_grad():
            weights = torch.zeros((in_channels, in_channels, 5, 5))
            for c in range(in_channels):
                weights[c, c] = torch.from_numpy(kv_kernel)
            self.kv_conv.weight.copy_(weights)
        # Freeze KV preprocessing layer
        self.kv_conv.weight.requires_grad = False

        # Group 1: Conv 5x5 -> ABS -> BN -> Tanh -> AvgPool 5x5 s2
        self.group1 = nn.Sequential(
            nn.Conv2d(in_channels, 8, kernel_size=5, stride=1, padding=2),
            ABS(),
            nn.BatchNorm2d(8),
            nn.Tanh(),
            nn.AvgPool2d(kernel_size=5, stride=2, padding=2)
        )

        # Group 2: Conv 5x5 -> BN -> Tanh -> AvgPool 5x5 s2
        self.group2 = nn.Sequential(
            nn.Conv2d(8, 16, kernel_size=5, stride=1, padding=2),
            nn.BatchNorm2d(16),
            nn.Tanh(),
            nn.AvgPool2d(kernel_size=5, stride=2, padding=2)
        )

        # Group 3: Conv 1x1 -> BN -> ReLU -> Conv 5x5 -> BN -> ReLU -> AvgPool 5x5 s2
        self.group3 = nn.Sequential(
            nn.Conv2d(16, 32, kernel_size=1, stride=1, padding=0),
            nn.BatchNorm2d(32),
            nn.ReLU(inplace=True),
            nn.Conv2d(32, 64, kernel_size=5, stride=1, padding=2),
            nn.BatchNorm2d(64),
            nn.ReLU(inplace=True),
            nn.AvgPool2d(kernel_size=5, stride=2, padding=2)
        )

        # Group 4: Conv 1x1 -> BN -> ReLU -> Conv 5x5 -> BN -> ReLU -> AvgPool 5x5 s2
        self.group4 = nn.Sequential(
            nn.Conv2d(64, 64, kernel_size=1, stride=1, padding=0),
            nn.BatchNorm2d(64),
            nn.ReLU(inplace=True),
            nn.Conv2d(64, 128, kernel_size=5, stride=1, padding=2),
            nn.BatchNorm2d(128),
            nn.ReLU(inplace=True),
            nn.AvgPool2d(kernel_size=5, stride=2, padding=2)
        )

        # Group 5: Conv 1x1 -> BN -> ReLU -> Conv 5x5 -> BN -> ReLU -> Global Adaptive Pool
        self.group5 = nn.Sequential(
            nn.Conv2d(128, 128, kernel_size=1, stride=1, padding=0),
            nn.BatchNorm2d(128),
            nn.ReLU(inplace=True),
            nn.Conv2d(128, 256, kernel_size=5, stride=1, padding=2),
            nn.BatchNorm2d(256),
            nn.ReLU(inplace=True),
            nn.AdaptiveAvgPool2d((1, 1))
        )

        # Fully connected classification head
        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(256, 128),
            nn.ReLU(inplace=True),
            nn.Dropout(p=0.4),
            nn.Linear(128, num_classes)
        )

    def forward(self, x):
        # 1. High-Pass Preprocessing Residual Extraction
        residual = self.kv_conv(x)

        # 2. Convolutional Representation Layers
        out = self.group1(residual)
        out = self.group2(out)
        out = self.group3(out)
        out = self.group4(out)
        out = self.group5(out)

        # 3. Dense Classifier Head
        logits = self.classifier(out)
        return logits
