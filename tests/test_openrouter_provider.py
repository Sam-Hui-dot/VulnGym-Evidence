from __future__ import annotations

import io
import json
import os
import unittest
from unittest.mock import patch

from vulngym_agent.openrouter_provider import _sanitize_error_body, build_payload, call_openrouter, parse_response


def semantic_request() -> dict:
    return {
        "task": "judge",
        "entry_id": "entry-1",
        "output_schema": {
            "type": "object",
            "properties": {"entry_id": {"type": "string"}},
            "required": ["entry_id"],
            "additionalProperties": False,
        },
    }


class FakeHttpResponse:
    def __init__(self, value: dict) -> None:
        self.raw = json.dumps(value).encode("utf-8")

    def __enter__(self) -> "FakeHttpResponse":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def read(self) -> bytes:
        return self.raw


class OpenRouterProviderTests(unittest.TestCase):
    def test_payload_requests_strict_structured_output(self) -> None:
        payload = build_payload(semantic_request(), "stealth/ox-alpha")
        self.assertEqual(payload["model"], "stealth/ox-alpha")
        self.assertTrue(payload["response_format"]["json_schema"]["strict"])
        self.assertNotIn("output_schema", json.loads(payload["messages"][1]["content"]))

    def test_parses_result_and_usage_metadata(self) -> None:
        parsed = parse_response(
            {
                "id": "generation-1",
                "model": "stealth/ox-alpha",
                "provider": "Stealth",
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": '{"entry_id":"entry-1"}'},
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "cost": 0},
            },
            "stealth/ox-alpha",
        )
        self.assertEqual(parsed["result"], {"entry_id": "entry-1"})
        self.assertEqual(parsed["metadata"]["provider"], "Stealth")
        self.assertEqual(parsed["metadata"]["usage"]["prompt_tokens"], 10)

    def test_call_sends_key_but_never_returns_it(self) -> None:
        response = {
            "choices": [{"finish_reason": "stop", "message": {"content": '{"entry_id":"entry-1"}'}}]
        }
        captured = {}

        def fake_urlopen(request, timeout):
            captured["authorization"] = request.headers["Authorization"]
            captured["timeout"] = timeout
            return FakeHttpResponse(response)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = call_openrouter(
                semantic_request(),
                api_key="test-secret",
                model="stealth/ox-alpha",
                timeout_seconds=30,
            )
        self.assertEqual(captured["authorization"], "Bearer test-secret")
        self.assertEqual(captured["timeout"], 30)
        self.assertNotIn("test-secret", json.dumps(result))

    def test_missing_key_fails_without_network(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "OPENROUTER_API_KEY is not set"):
            call_openrouter(semantic_request(), api_key="", model="stealth/ox-alpha")

    def test_error_body_removes_openrouter_user_identifier(self) -> None:
        sanitized = _sanitize_error_body(
            '{"error":{"message":"model unavailable","code":404},"user_id":"user-private"}'
        )
        self.assertNotIn("user-private", sanitized)
        self.assertEqual(json.loads(sanitized)["error"]["code"], 404)


if __name__ == "__main__":
    unittest.main()
