"""
AegisLEO Phase 5 - Sequence Autoencoder Training Script

What this does:
- Loads telemetry CSV
- Converts it into sliding windows (time sequences)
- Trains a neural network to reconstruct "normal" behavior
- Saves model + anomaly threshold

Key idea:
If reconstruction error is high later → anomaly detected
"""

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
import json
import os

# This builds sliding windows from your CSV
from window_dataset import build_windows


# TEMP path (you said this is intentional)
DATA_PATH = "groundstation/logs/telemetry_normal.csv"
#DATA_PATH = "groundstation/logs/telemetry_normal.csv"

# Where trained model will be saved
MODEL_PATH = "models/seq_autoencoder.pt"

# Where anomaly threshold will be saved
THRESHOLD_PATH = "models/seq_threshold.json"

# Number of time steps per sequence
WINDOW_SIZE = 4

# Training batch size
BATCH_SIZE = 8

# Number of training passes
EPOCHS = 100


# ================================
# 🧠 Model Definition
# ================================
class SeqAutoencoder(nn.Module):
    """
    Simple feedforward autoencoder applied across time windows.

    Input shape:
        (batch, window, features)

    It learns to compress → reconstruct "normal" telemetry behavior.
    """

    def __init__(self, features):
        super().__init__()

        # Encoder compresses input
        self.encoder = nn.Sequential(
            nn.Linear(features, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
        )

        # Decoder reconstructs input
        self.decoder = nn.Sequential(
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, features),
        )

    def forward(self, x):
        # Apply encoder then decoder
        z = self.encoder(x)
        out = self.decoder(z)
        return out


# ================================
# 🚀 Training Pipeline
# ================================
def main():

    # Detect GPU
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"\nUsing device: {device}")

    if device == "cuda":
        print(f"CUDA device: {torch.cuda.get_device_name(0)}")

    # ============================
    # 📊 Load dataset
    # ============================
    print("\nLoading dataset...")

    X = build_windows(DATA_PATH, WINDOW_SIZE)

    # 🔥 Critical safety check
    if len(X) == 0:
        raise ValueError(
            f"\nNo windows created!\n"
            f"Your dataset is too small or missing.\n"
            f"Need more rows than WINDOW_SIZE={WINDOW_SIZE}"
        )

    print(f"Dataset windows shape: {X.shape}")

    # Convert to PyTorch tensor
    X = torch.tensor(X, dtype=torch.float32)

    # Autoencoder learns input → output (same)
    dataset = TensorDataset(X, X)

    loader = DataLoader(dataset, 
                        batch_size=BATCH_SIZE, 
                        shuffle=True,
                        num_workers=0,
                        pin_memory=False)

    # ============================
    # 🧠 Build model
    # ============================
    features = X.shape[2]

    model = SeqAutoencoder(features).to(device)

    print("\nModel architecture:")
    print(model)

    # Optimizer = how model learns
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-4)

    # Loss = reconstruction error
    loss_fn = nn.MSELoss()

    # ============================
    # Training loop
    # ============================
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = nn.MSELoss()

    print("\nStarting training...\n")

    for epoch in range(EPOCHS):
        model.train()
        total_loss = 0.0

        for batch_x, _ in loader:
            batch_x = batch_x.to(device, non_blocking=False)

            optimizer.zero_grad(set_to_none=True)

            pred = model(batch_x)
            loss = loss_fn(pred, batch_x)

            loss.backward()
            optimizer.step()

            total_loss += loss.item()

            # Free batch refs quickly on Jetson
            del batch_x, pred, loss

        if device == "cuda":
            torch.cuda.empty_cache()

        print(f"Epoch {epoch + 1}/{EPOCHS} → loss={total_loss:.6f}")

    # ============================
    # 📈 Compute anomaly threshold
    # ============================
    print("\nComputing anomaly threshold...")

    model.eval()

    with torch.no_grad():
        recon = model(X.to(device)).cpu().numpy()

        # Mean squared reconstruction error per window
        errors = np.mean((X.numpy() - recon) ** 2, axis=(1, 2))

    # Threshold = mean + 3 standard deviations
    threshold = float(np.mean(errors) + 3 * np.std(errors))

    print(f"Threshold calculated: {threshold}")

    # ============================
    # 💾 Save artifacts
    # ============================
    os.makedirs("models", exist_ok=True)

    torch.save(model.state_dict(), MODEL_PATH)

    with open(THRESHOLD_PATH, "w") as f:
        json.dump({"threshold": threshold}, f, indent=2)

    print("\nTraining complete.")
    print(f"Model saved → {MODEL_PATH}")
    print(f"Threshold saved → {THRESHOLD_PATH}")


# ================================
# 🎬 Entry point
# ================================
if __name__ == "__main__":
    main()
