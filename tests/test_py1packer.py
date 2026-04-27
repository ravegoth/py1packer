import base64
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import py1packer


class Py1PackerTests(unittest.TestCase):
    def test_non_recursive_gathering_ignores_child_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "top.txt").write_text("top", encoding="utf-8")
            (root / "child").mkdir()
            (root / "child" / "nested.txt").write_text("nested", encoding="utf-8")

            files, directories = py1packer.gather_files(str(root), [], recursive=False)

            self.assertEqual(files, ["top.txt"])
            self.assertEqual(directories, [])

    def test_cli_increment_policy_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src"
            root.mkdir()
            (root / "payload.txt").write_text("payload", encoding="utf-8")
            output = Path(tmp) / "packed.py"
            output.write_text("existing", encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(py1packer.__file__).resolve()),
                    str(root),
                    "-o",
                    str(output),
                    "--overwrite",
                    "increment",
                ],
                cwd=tmp,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_text(encoding="utf-8"), "existing")
            self.assertTrue((Path(tmp) / "packed_2.py").exists())

    def test_pack_directory_reports_skip_policy_without_exiting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src"
            root.mkdir()
            (root / "payload.txt").write_text("payload", encoding="utf-8")
            output = Path(tmp) / "packed.py"
            output.write_text("existing", encoding="utf-8")

            with self.assertRaises(py1packer.PackerError):
                py1packer.pack_directory(str(root), str(output), overwrite="skip")

            self.assertEqual(output.read_text(encoding="utf-8"), "existing")

    def test_extractor_creates_parent_directories_for_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "extract.py"
            data = {"nested/payload.txt": base64.b64encode(b"payload").decode("ascii")}

            py1packer.build_extractor(data, [], str(script))
            result = subprocess.run(
                [sys.executable, str(script)],
                cwd=tmp,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((Path(tmp) / "nested" / "payload.txt").read_text(encoding="utf-8"), "payload")


if __name__ == "__main__":
    unittest.main()
