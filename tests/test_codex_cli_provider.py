from __future__ import annotations

import unittest
from pathlib import Path

import json

from vulngym_agent.codex_cli_provider import _parse_codex_events, _powershell_quote


class CodexCliProviderTests(unittest.TestCase):
    def test_powershell_single_quote_escaping(self) -> None:
        self.assertEqual(_powershell_quote("C:\\Sam's Files\\x"), "'C:\\Sam''s Files\\x'")

    def test_parses_usage_from_jsonl_events(self) -> None:
        events = [
            {"type": "thread.started", "thread_id": "thread-1"},
            {"type": "turn.started"},
            {
                "type": "turn.completed",
                "usage": {
                    "input_tokens": 100,
                    "cached_input_tokens": 80,
                    "output_tokens": 12,
                    "reasoning_output_tokens": 3,
                },
            },
        ]
        raw = "\n".join(json.dumps(event) for event in events).encode("utf-8")
        metadata = _parse_codex_events(raw)
        self.assertEqual(metadata["thread_id"], "thread-1")
        self.assertEqual(metadata["usage"]["input_tokens"], 100)
        self.assertEqual(metadata["event_counts"]["turn.completed"], 1)


if __name__ == "__main__":
    unittest.main()
