"""Fixed public example only: no secrets, uploads, online inference or private jobs."""
from __future__ import annotations
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from vulngym_evidence.server import serve_local

if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    origin = os.environ.get("PUBLIC_DEMO_ORIGIN", "").strip().rstrip("/")
    if not origin:
        raise SystemExit("Set PUBLIC_DEMO_ORIGIN to the application's actual HTTP(S) origin, without a path.")
    serve_local(port=int(os.environ.get("PORT", "7860")),
        output_dir=Path(os.environ.get("DEMO_OUTPUT_DIR", "/mnt/workspace/evidence-example")),
        configuration={"provider": None, "roots": [], "repository": None,
                       "advisory_documents": [], "use_critic": False},
        public_origin=origin)
