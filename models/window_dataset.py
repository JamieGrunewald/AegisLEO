import numpy as np
import pandas as pd


FEATURE_COLUMNS = [
    "seq",
    "temperature_c",
    "battery_pct",
    "latitude",
    "longitude",
    "altitude_km",
    "bus_v",
    "bus_i",
    "mode_nominal",
    "mode_sunpoint",
    "mode_tx_window",
]


def build_windows(csv_path: str, window_size: int = 16):
    df = pd.read_csv(csv_path)

    X = df[FEATURE_COLUMNS].values.astype(np.float32)

    windows = []
    for i in range(len(X) - window_size):
        windows.append(X[i : i + window_size])

    return np.array(windows)