"""Check the shipped second example against its offline fixed source, without AI."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from vulngym_evidence.contract import validate_request
from vulngym_evidence.runtime import inspect_repository
from vulngym_evidence.workflow import verify_request


ROOT = Path(__file__).resolve().parents[1]


class TeachingExampleTests(unittest.TestCase):
    def example(self):
        catalog = json.loads((ROOT / "src/vulngym_evidence/web/examples.json").read_text(encoding="utf-8"))
        return catalog["examples"][0]

    def test_report_and_prepared_claims_preserve_exact_origins_and_have_no_results(self):
        example = self.example()
        value = validate_request(example["request"])
        self.assertEqual(len(value["claims"]), 3)
        self.assertNotIn("results", example)
        for claim in value["claims"]:
            origin = claim["origin"]
            self.assertEqual(value["report_text"][origin["start"]:origin["end"]], origin["quote"])
        prepared = json.loads((ROOT / "docs/examples/starlette-input.json").read_text(encoding="utf-8"))
        self.assertEqual(prepared, example["request"])
        self.assertIn("Redistribution and use", (ROOT / "docs/examples/STARLETTE_LICENSE.md").read_text(encoding="utf-8"))

    @unittest.skipUnless(shutil.which("git"), "Git is required")
    def test_launcher_prepares_offline_source_and_all_three_quoted_locations_match(self):
        spec = importlib.util.spec_from_file_location("desktop_launcher", ROOT / "scripts/start_desktop.py")
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher.prepare_bundled_source(root)
            value = deepcopy(self.example()["request"])
            state = inspect_repository({key: value[key] for key in ("repo_url", "reviewed_commit")}, roots=[root])
            self.assertTrue(state["ready"])
            # Only validate quoted source locations; this does not assess their meaning.
            for claim in value["claims"]:
                claim["kind"] = "source_location"
                claim["text"] = "所列版本、文件、行号与引用代码一致。"
            result = verify_request(value, roots=[root], provider=None)
            self.assertEqual(result["model_calls"], [])
            self.assertEqual([row["verdict"] for row in result["results"]], ["supported"] * 3)
            launcher.prepare_bundled_source(root)  # Existing user material is retained.
            self.assertTrue((root / "encode/starlette/.git").exists())
