import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts" / "demo" / "weknora.json"


class DemoArtifactTests(unittest.TestCase):
    def test_artifact_has_all_submission_fields(self) -> None:
        data = json.loads(ARTIFACT.read_text(encoding="utf-8"))
        self.assertEqual(
            set(data["final_report"]),
            {
                "entry_point",
                "critical_operation",
                "vuln_category_l1",
                "vuln_category_l2",
                "vuln_title",
                "vuln_ids",
                "commit",
                "trace",
            },
        )
        self.assertEqual(data["result"], "incorrect")

    def test_demo_command_renders_human_readable_result(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "show_demo.py")],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("WeKnora", completed.stdout)
        self.assertIn("关键操作", completed.stdout)
        self.assertIn("总体结论：✗ 错误", completed.stdout)


if __name__ == "__main__":
    unittest.main()
