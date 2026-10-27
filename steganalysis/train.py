"""
train.py
--------
Training and evaluation script for Xu-Net Steganalysis detector.

Trains on pairs of Clean (0) vs Stego (1) images containing multimodal prompt injections.
Evaluates:
  - Binary Accuracy
  - Precision, Recall, F1-Score
  - False Positive Rate (FPR) and False Negative Rate (FNR)
  - Saves optimal checkpoint for Gateway inference.
"""

import argparse
import os
import glob
import random
from typing import Tuple, List

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from PIL import Image
from torchvision import transforms

from .xunet import XuNet


class StegoDataset(Dataset):
    def __init__(self, file_paths: List[str], labels: List[int], transform=None):
        self.file_paths = file_paths
        self.labels = labels
        self.transform = transform

    def __len__(self):
        return len(self.file_paths)

    def __getitem__(self, idx):
        path = self.file_paths[idx]
        label = self.labels[idx]
        image = Image.open(path).convert("L")  # Grayscale for standard steganalysis or RGB
        if self.transform:
            image = self.transform(image)
        return image, torch.tensor(label, dtype=torch.long)


def get_data_loaders(
    data_dir: str = "dataset/data",
    batch_size: int = 16,
    val_split: float = 0.2,
    img_size: int = 256,
) -> Tuple[DataLoader, DataLoader]:
    clean_paths = glob.glob(os.path.join(data_dir, "clean", "*.png"))
    stego_paths = glob.glob(os.path.join(data_dir, "stego", "*.png"))

    if not clean_paths or not stego_paths:
        raise FileNotFoundError(
            f"Dataset not found in {data_dir}. Run 'python -m dataset.generate_dataset' first!"
        )

    # Balance datasets
    min_count = min(len(clean_paths), len(stego_paths))
    clean_paths = clean_paths[:min_count]
    stego_paths = stego_paths[:min_count]

    all_paths = clean_paths + stego_paths
    all_labels = [0] * len(clean_paths) + [1] * len(stego_paths)

    combined = list(zip(all_paths, all_labels))
    random.seed(42)
    random.shuffle(combined)
    all_paths, all_labels = zip(*combined)

    val_size = int(len(all_paths) * val_split)
    train_paths, train_labels = all_paths[val_size:], all_labels[val_size:]
    val_paths, val_labels = all_paths[:val_size], all_labels[:val_size]

    transform = transforms.Compose([
        transforms.Resize((img_size, img_size)),
        transforms.ToTensor(),
        # Normalize to [-1, 1] range to suit steganalysis residue distribution
        transforms.Normalize(mean=[0.5], std=[0.5]),
    ])

    train_dataset = StegoDataset(list(train_paths), list(train_labels), transform=transform)
    val_dataset = StegoDataset(list(val_paths), list(val_labels), transform=transform)

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, drop_last=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)

    return train_loader, val_loader


def train_model(
    data_dir: str = "dataset/data",
    epochs: int = 10,
    batch_size: int = 16,
    lr: float = 1e-3,
    save_path: str = "steganalysis/model_weights/xunet_best.pth",
):
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[*] Training Xu-Net on device: {device}")

    train_loader, val_loader = get_data_loaders(data_dir=data_dir, batch_size=batch_size)
    print(f"[*] Total training batches: {len(train_loader)} | Validation batches: {len(val_loader)}")

    model = XuNet(in_channels=1, num_classes=2).to(device)
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adamax(filter(lambda p: p.requires_grad, model.parameters()), lr=lr, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    best_val_acc = 0.0

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss, correct, total = 0.0, 0, 0

        for images, labels in train_loader:
            images, labels = images.to(device), labels.to(device)

            optimizer.zero_grad()
            outputs = model(images)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()

            total_loss += loss.item() * images.size(0)
            preds = torch.argmax(outputs, dim=1)
            correct += (preds == labels).sum().item()
            total += labels.size(0)

        scheduler.step()
        train_acc = correct / total if total > 0 else 0
        avg_loss = total_loss / total if total > 0 else 0

        # Validation
        model.eval()
        val_correct, val_total = 0, 0
        tp, fp, tn, fn = 0, 0, 0, 0

        with torch.no_grad():
            for images, labels in val_loader:
                images, labels = images.to(device), labels.to(device)
                outputs = model(images)
                preds = torch.argmax(outputs, dim=1)

                val_correct += (preds == labels).sum().item()
                val_total += labels.size(0)

                for p, t in zip(preds, labels):
                    if p == 1 and t == 1:
                        tp += 1
                    elif p == 1 and t == 0:
                        fp += 1
                    elif p == 0 and t == 0:
                        tn += 1
                    elif p == 0 and t == 1:
                        fn += 1

        val_acc = val_correct / val_total if val_total > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        print(
            f"Epoch [{epoch:02d}/{epochs:02d}] "
            f"Loss: {avg_loss:.4f} | Train Acc: {train_acc*100:.2f}% | "
            f"Val Acc: {val_acc*100:.2f}% | F1: {f1:.4f} (TP:{tp} FP:{fp} TN:{tn} FN:{fn})"
        )

        if val_acc > best_val_acc or epoch == epochs:
            best_val_acc = val_acc
            torch.save({
                "model_state_dict": model.state_dict(),
                "val_accuracy": val_acc,
                "epoch": epoch,
            }, save_path)
            print(f"    [+] Saved checkpoint -> {save_path} (Acc: {val_acc*100:.2f}%)")

    print(f"\n[+] Xu-Net Training Complete. Peak Validation Accuracy: {best_val_acc*100:.2f}%")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Xu-Net Steganalysis model.")
    parser.add_argument("--data-dir", default="dataset/data", help="Path to dataset root.")
    parser.add_argument("--epochs", type=int, default=10, help="Number of training epochs.")
    parser.add_argument("--batch-size", type=int, default=16, help="Batch size.")
    parser.add_argument("--lr", type=float, default=1e-3, help="Learning rate.")
    parser.add_argument("--save-path", default="steganalysis/model_weights/xunet_best.pth", help="Checkpoint save path.")
    args = parser.parse_args()

    train_model(args.data_dir, args.epochs, args.batch_size, args.lr, args.save_path)
