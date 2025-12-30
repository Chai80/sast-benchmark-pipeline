"""tools/aikido

Aikido scanner package (Option B).

`tools/scan_aikido.py` remains the stable script entrypoint used by the pipeline.
"""

from .runner import cli_entry, execute, RunPaths, AikidoConfig  # noqa: F401
