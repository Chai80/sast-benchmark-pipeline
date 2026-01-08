import unittest
from pathlib import Path
import tempfile


from tools.io import read_line_content


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
            self.assertIsNone(read_line_content(repo_root, str(root / "outside.txt"), 1))


if __name__ == "__main__":
    unittest.main()
