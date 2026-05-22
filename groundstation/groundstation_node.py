"""
AegisLEO — Ground Station Node Orchestrator
=============================================

Created by: Jamie Grunewald
Date: 2026-03-26
Version: v0.1.0 (stub)

Purpose
-------
Planned top-level orchestrator for the ground station node. In the current
pipeline, groundstation/receiver.py runs as a standalone script with its
main receive loop at module level.

This module is reserved for v2.0 refactoring, where the ground station will
be structured as a proper service with clean startup, shutdown, and health
monitoring.

Planned functionality
---------------------
- Initialize all ground station components (serial link, key material,
  ReassemblyFactory, ReplayWindow, RuntimeDetector, FeatureLogger)
- Run the main receive loop as a managed service
- Handle SIGTERM/SIGINT gracefully with clean shutdown
- Expose health status for monitoring (InfluxDB / Grafana in v2.0)
- Support hot-reload of key material without restarting

Planned usage
-------------
    python -m groundstation.groundstation_node

See also
--------
- groundstation/receiver.py     — current active receive loop
- groundstation/reassembly.py   — chunk reassembly (ReassemblyFactory)
- groundstation/replay_window.py — replay protection
- groundstation/feature_logger.py — ML training data collection
- docs/architecture.md          — system architecture overview
"""

# TODO: implement GroundStationNode service wrapper for v2.0
