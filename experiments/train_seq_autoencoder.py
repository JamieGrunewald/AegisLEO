import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
import json
import os

from window_dataset import build_windows

DATA_PATH = "groundstation/logs/_generated_telemetry.csv"
#DATA_PATH = "groundstation/logs/telemetry_normal.csv"

MODEL_PATH = "models/seq_autoencoder.pt"
THRESHOLD_PATH = "models/seq_threshold.json"

WINDOW_SIZE = 16
BATCH_SIZE = 32
EPOCHS = 25


class SeqAutoencoder(nn.Module):
    def __init__(self, features):
        super().__init__()

        self.encoder = nn.Sequential(
            nn.Linear(features, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
        )

        self.decoder = nn.Sequential(
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, features),
        )

    def forward(self, x):
        # x: (batch, window, features)
        z = self.encoder(x)
        out = self.decoder(z)
        return out


def main():
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"Using device: {device}")
    if device == "cuda":
        print(f"CUDA device: {torch.cuda.get_device_name(0)}")
    print(model)

    X = build_windows(DATA_PATH, WINDOW_SIZE)

    X = torch.tensor(X)
    dataset = TensorDataset(X, X)

    loader = DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True)

    features = X.shape[2]
    model = SeqAutoencoder(features).to(device)

    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = nn.MSELoss()

    for epoch in range(EPOCHS):
        total_loss = 0

        for batch_x, _ in loader:
            batch_x = batch_x.to(device)

            pred = model(batch_x)
            loss = loss_fn(pred, batch_x)

            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

            total_loss += loss.item()

        print(f"Epoch {epoch+1}: loss={total_loss:.6f}")

    # compute threshold
    model.eval()
    with torch.no_grad():
        recon = model(X.to(device)).cpu().numpy()
        errors = np.mean((X.numpy() - recon) ** 2, axis=(1, 2))

    threshold = float(np.mean(errors) + 3 * np.std(errors))

    os.makedirs("models", exist_ok=True)
    torch.save(model.state_dict(), MODEL_PATH)

    with open(THRESHOLD_PATH, "w") as f:
        json.dump({"threshold": threshold}, f)

    print(f"Saved model. Threshold={threshold}")


if __name__ == "__main__":
    main()