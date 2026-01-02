"""Analysis stages for the SAST benchmarking pipeline.

Each module is designed to be runnable as:
    python -m pipeline.analysis.<module>

And also importable by orchestrators (e.g. analyze_suite).

Design goals:
- filesystem artifacts only (JSON/CSV)
- deterministic outputs for reproducible comparisons
- minimal shared helpers to avoid signature drift / spaghetti
"""
