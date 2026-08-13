# Contributing to AegisLEO

Thank you for your interest in the project.

AegisLEO is a personal research testbed. It is shared publicly so that others can inspect the design, reproduce the results, and learn from the same constraints I encountered.

## Current Status

The core system (PQC session establishment, CCSDS-inspired framing, chunking/NACK, ML anomaly detection, and adversarial injection) is functional and was the basis of the CypherCon 9 presentation (April 2026). The presentation used screenshots and recorded results from a home demonstration; a live RF demo was not run at the conference.

Several v2.0 components are still stubs or incomplete. These are clearly marked in the code and in the Roadmap section of the README.

## How to Run the Existing System

Follow the **Getting Started** section in the root `README.md`. You will need:

- Python 3.10+
- liboqs + liboqs-python (built from source)
- Either the physical hardware (Raspberry Pi 5 + Jetson Orin + SX1262 LoRa HATs) or a serial loopback configuration for local testing

## Reporting Issues

If you find a bug, an unclear section in the documentation, or a reproducibility problem, please open a GitHub issue. Include:

- What you were trying to do
- Hardware / OS / Python version
- Exact error messages or unexpected behavior
- Steps to reproduce

## Pull Requests

Small, well-scoped improvements are welcome, especially:

- Documentation clarifications
- Bug fixes in the current working path
- Additional tests
- Benchmark or measurement scripts

Please keep changes focused. Large refactors or new features should be discussed in an issue first.

## Design Philosophy

This project prioritizes:

1. Measurable behavior on real (or realistically constrained) hardware
2. Clear separation between cryptographic verification and behavioral detection
3. Honest documentation of limitations and trade-offs

If a proposed change moves the project away from these principles, it is unlikely to be accepted.

## License

By contributing, you agree that your contributions will be licensed under the MIT License that covers this repository.
