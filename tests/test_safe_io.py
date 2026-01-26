import unittest
from pathlib import Path
import tempfile


from tools.io import read_json, read_line_content, write_json


class TestSafeIO(unittest.TestCase):
    def test_read_line_content_blocks_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo_root = root / "repo"
            repo_root.mkdir()
            (repo_root / "inside.txt").write_text("hello\n", encoding="utf-8")
            (root / "outside.txt").write_text("outside\n", encoding="utf-8")

            # Direct file works
            self.assertEqual("hello", read_line_content(repo_root, "inside.txt", 1))

            # Traversal should be denied (returns None)
            self.assertIsNone(read_line_content(repo_root, "../outside.txt", 1))

            # Absolute path outside should be denied (returns None)
            self.assertIsNone(
                read_line_content(repo_root, str(root / "outside.txt"), 1)
            )

    def test_write_json_is_atomic_and_cleans_temp(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            out_dir = root / "out"
            out_path = out_dir / "state.json"

            payload = {"a": 1, "b": True, "c": None, "nested": {"x": "y"}}
            write_json(out_path, payload)

            # File written and readable
            self.assertTrue(out_path.exists())
            self.assertEqual(payload, read_json(out_path))

            # No temp files left behind on success
            tmp_files = list(out_dir.glob("*.tmp"))
            self.assertEqual([], tmp_files)


if __name__ == "__main__":
    unittest.main()
