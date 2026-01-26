import unittest
from pathlib import Path

from pipeline.scanners import (
    DEFAULT_SCANNERS,
    DEFAULT_SCANNERS_CSV,
    SCANNERS,
    SCANNER_SCRIPTS,
    SCANNER_TARGET_MODES,
    SCANNER_TRACKS,
    SUPPORTED_SCANNERS,
)


class TestScannerRegistry(unittest.TestCase):
    def test_registry_keys_are_consistent(self) -> None:
        self.assertEqual(set(SCANNERS.keys()), SUPPORTED_SCANNERS)
        self.assertEqual(set(SCANNER_SCRIPTS.keys()), SUPPORTED_SCANNERS)
        self.assertEqual(set(SCANNER_TARGET_MODES.keys()), SUPPORTED_SCANNERS)
        self.assertEqual(set(SCANNER_TRACKS.keys()), SUPPORTED_SCANNERS)

    def test_default_scanners_csv_matches_list(self) -> None:
        self.assertTrue(DEFAULT_SCANNERS, "DEFAULT_SCANNERS should not be empty")
        self.assertEqual(DEFAULT_SCANNERS_CSV, ",".join(DEFAULT_SCANNERS))
        self.assertEqual(
            len(DEFAULT_SCANNERS),
            len(set(DEFAULT_SCANNERS)),
            "DEFAULT_SCANNERS should not contain duplicates",
        )
        for s in DEFAULT_SCANNERS:
            self.assertIn(s, SUPPORTED_SCANNERS)

    def test_scanner_scripts_exist_under_tools(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        tools_dir = repo_root / "tools"
        for key, script_name in SCANNER_SCRIPTS.items():
            p = tools_dir / script_name
            self.assertTrue(p.exists(), f"Missing script for {key!r}: {p}")

    def test_scanner_tracks_are_non_empty_and_lowercase(self) -> None:
        for key, tracks in SCANNER_TRACKS.items():
            self.assertTrue(tracks, f"Scanner {key!r} should declare at least one track")
            for t in tracks:
                self.assertEqual(
                    t, t.lower(), f"Track {t!r} for scanner {key!r} should be lowercase"
                )

    def test_scanner_target_modes_are_declared(self) -> None:
        for key, mode in SCANNER_TARGET_MODES.items():
            self.assertIn(
                mode,
                {"repo", "git-ref"},
                f"Unexpected target_mode for {key!r}: {mode!r}",
            )

    def test_scanner_required_env_and_hooks(self) -> None:
        # Sonar should declare env requirements and a hook to derive project-key
        sonar = SCANNERS["sonar"]
        self.assertIn("SONAR_ORG", sonar.required_env)
        self.assertIn("SONAR_TOKEN", sonar.required_env)
        self.assertTrue(callable(sonar.extra_args_builder))

        # Aikido uses a git-ref target mode and typically requires API credentials
        aikido = SCANNERS["aikido"]
        self.assertEqual("git-ref", SCANNER_TARGET_MODES["aikido"])
        self.assertIn("AIKIDO_CLIENT_ID", aikido.required_env)
        self.assertIn("AIKIDO_CLIENT_SECRET", aikido.required_env)
        self.assertTrue(callable(aikido.extra_args_builder))


if __name__ == "__main__":
    unittest.main()
