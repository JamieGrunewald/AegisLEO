from __future__ import annotations

"""
AegisLEO Phase 5 - Runtime Sequence Detector

What this does:
- Loads the trained sequence autoencoder
- Keeps a rolling window of recent telemetry feature vectors
- Reconstructs that window using the trained model
- Computes reconstruction error
- Flags anomaly if score > saved threshold
"""

import json
from collections import deque
from dataclasses import dataclass
from pathlib import Path

import torch
import torch.nn as nn


# Must match training script
WINDOW_SIZE = 4
MODEL_PATH = Path("models/seq_autoencoder.pt")
THRESHOLD_PATH = Path("models/seq_threshold.json")


@dataclass
class DetectionResult:
    is_anomalous: bool
    score: float
    reasons: list[str]


class SeqAutoencoder(nn.Module):
    """
    Same model architecture used during training.
    Must match exactly or the saved weights will not load.
    """

    def __init__(self, features: int):
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
        z = self.encoder(x)
        out = self.decoder(z)
        return out


class RuntimeDetector:
    """
    Runtime anomaly detector for live telemetry.

    Behavior:
    - If model is not loaded yet, returns a safe nominal placeholder
    - If window is not full yet, returns warming_up
    - Once window is full, computes real anomaly score
    """

    def __init__(self):
        self.ready = False
        self.threshold = None
        self.window: deque[list[float]] = deque(maxlen=WINDOW_SIZE)

        # Runtime inference can stay on CPU for now.
        # Training used GPU. Live inference for this small model is light.
        self.device = "cpu"

        try:
            if not MODEL_PATH.exists():
                raise FileNotFoundError(f"Missing model file: {MODEL_PATH}")

            if not THRESHOLD_PATH.exists():
                raise FileNotFoundError(f"Missing threshold file: {THRESHOLD_PATH}")

            # Load threshold
            with open(THRESHOLD_PATH, "r") as f:
                cfg = json.load(f)

            self.threshold = float(cfg["threshold"])

            # Feature count must match telemetry.to_feature_vector()
            self.model = SeqAutoencoder(features=11).to(self.device)

            state_dict = torch.load(MODEL_PATH, map_location=self.device)
            self.model.load_state_dict(state_dict)
            self.model.eval()

            self.ready = True

        except Exception as exc:
            print(f"[ML] RuntimeDetector init failed: {exc}", flush=True)
            self.ready = False

    def detect(self, telemetry) -> DetectionResult:
        """
        Score one live telemetry object.

        telemetry must provide:
        - to_feature_vector()
        - validate_envelope()
        """

        # Convert live telemetry object into numeric feature vector
        features = list(telemetry.to_feature_vector())
        self.window.append(features)

        # Model not loaded yet
        if not self.ready:
            return DetectionResult(
                is_anomalous=False,
                score=0.0,
                reasons=["model_not_loaded"],
            )

        # Need enough history before we can score a sequence
        if len(self.window) < WINDOW_SIZE:
            return DetectionResult(
                is_anomalous=False,
                score=0.0,
                reasons=["warming_up"],
            )

        # Build one input tensor shaped like:
        # (batch=1, window_size, features)
        x = torch.tensor([list(self.window)], dtype=torch.float32, device=self.device)

        with torch.no_grad():
            pred = self.model(x)
            error = torch.mean((x - pred) ** 2).item()

        is_anomalous = error > self.threshold

        # Add human-readable reasons for stage output
        reasons = telemetry.validate_envelope()

        return DetectionResult(
            is_anomalous=is_anomalous,
            score=error,
            reasons=reasons,
        )