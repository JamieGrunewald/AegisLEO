"""
AegisLEO — TCP Injection Bridge (alias)
========================================

Created by: Jamie Grunewald
Date: 2026-03-26
Version: v0.1.0

Purpose
-------
Thin alias retained from early development when the TCP-based and
Kali-side injection paths were being developed separately. The full
implementation now lives in kali-inj-bridge.py, which supports both
TCP bridge and direct serial injection modes.

Use kali-inj-bridge.py directly:
    python3 adversary/kali-inj-bridge.py --host 127.0.0.1 --port 5555
"""

from adversary.kali_inj_bridge import main

if __name__ == "__main__":
    main()
