"""sast_benchmark

New package namespace for the benchmark pipeline.

Why this exists
---------------
This repository historically organized code under top-level packages like
``tools`` and ``pipeline``.

As the project grows, it becomes valuable to establish a single "core" package
that owns:

* domain types (the canonical data contracts across tools)
* IO/layout rules (filesystem contracts across tools and analysis)

The goal is to make the CLI and tool entrypoints *thin composition roots* that
wire together reusable components.
"""

from __future__ import annotations
