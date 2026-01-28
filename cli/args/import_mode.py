from __future__ import annotations

import argparse


def add_import_mode_args(parser: argparse.ArgumentParser) -> None:
    """Register flags for `--mode import` (legacy run importer)."""

    parser.add_argument(
        "--import-run-id",
        default="latest",
        help=(
            "(import mode) Which legacy run_id folder to import for each tool. \n            Default: 'latest'. You can also pass an explicit run id like '20260101011234'."
        ),
    )
    parser.add_argument(
        "--import-link-mode",
        choices=["copy", "hardlink"],
        default="copy",
        help=(
            "(import mode) File transfer strategy when importing legacy outputs into a suite. \n            'copy' is safest; 'hardlink' is faster and saves disk when supported."
        ),
    )
