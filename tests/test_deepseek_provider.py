from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from vulngym_agent.deepseek_provider import (
    _reasoning_effort_env,
    _sanitize_error_body,
    build_payload,
    call_deepseek,
    parse_response,
)


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


class DeepSeekProviderTests(unittest.TestCase):
    def test_payload_requests_responses_json_schema(self) -> None:
        payload = build_payload(semantic_request(), "deepseek-v4-flash")
        self.assertEqual(payload["model"], "deepseek-v4-flash")
        self.assertEqual(payload["reasoning"], {"effort": "none"})
        self.assertEqual(payload["text"]["format"]["type"], "json_schema")
        self.assertEqual(payload["text"]["format"]["schema"]["required"], ["entry_id"])
        prompt = json.loads(payload["input"])
        self.assertNotIn("output_schema", prompt)

    def test_payload_supports_configurable_reasoning_effort(self) -> None:
        payload = build_payload(semantic_request(), "deepseek-v4-pro", "high")
        self.assertEqual(payload["reasoning"], {"effort": "high"})

    def test_invalid_reasoning_effort_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "reasoning_effort must be one of"):
            build_payload(semantic_request(), "deepseek-v4-pro", "turbo")

        with patch.dict("os.environ", {"TEST_REASONING_EFFORT": "turbo"}):
            with self.assertRaisesRegex(RuntimeError, "TEST_REASONING_EFFORT must be one of"):
                _reasoning_effort_env("TEST_REASONING_EFFORT")

    def test_parses_result_and_usage_metadata(self) -> None:
        parsed = parse_response(
            {
                "id": "completion-1",
                "model": "deepseek-v4-flash",
                "status": "completed",
                "system_fingerprint": "fp-1",
                "output": [
                    {
                        "type": "message",
                        "content": [
                            {"type": "output_text", "text": '{"entry_id":"entry-1"}'}
                        ],
                    }
                ],
                "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
            },
            "deepseek-v4-flash",
        )
        self.assertEqual(parsed["result"], {"entry_id": "entry-1"})
        self.assertEqual(parsed["metadata"]["transport"], "deepseek_responses")
        self.assertEqual(parsed["metadata"]["status"], "completed")
        self.assertEqual(parsed["metadata"]["requested_reasoning_effort"], "none")
        self.assertEqual(parsed["metadata"]["usage"]["total_tokens"], 15)

    def test_call_sends_key_but_never_returns_it(self) -> None:
        response = {
            "status": "completed",
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": '{"entry_id":"entry-1"}'}],
                }
            ],
        }
        captured = {}

        def fake_urlopen(request, timeout):
            captured["authorization"] = request.headers["Authorization"]
            captured["url"] = request.full_url
            captured["timeout"] = timeout
            return FakeHttpResponse(response)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = call_deepseek(
                semantic_request(),
                api_key="test-secret",
                model="deepseek-v4-flash",
                enabled=True,
                timeout_seconds=30,
            )
        self.assertEqual(captured["authorization"], "Bearer test-secret")
        self.assertEqual(captured["url"], "https://api.deepseek.com/responses")
        self.assertEqual(captured["timeout"], 30)
        self.assertNotIn("test-secret", json.dumps(result))

    def test_disabled_fails_before_network(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "DeepSeek calls are disabled"):
            call_deepseek(
                semantic_request(),
                api_key="test-secret",
                model="deepseek-v4-flash",
                enabled=False,
            )

    def test_missing_key_fails_before_network(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "DEEPSEEK_API_KEY is not set"):
            call_deepseek(
                semantic_request(),
                api_key="",
                model="deepseek-v4-flash",
                enabled=True,
            )

    def test_error_body_removes_private_identifiers(self) -> None:
        sanitized = _sanitize_error_body(
            '{"error":{"message":"denied"},"user_id":"private-user","api_key":"private-key"}'
        )
        self.assertNotIn("private-user", sanitized)
        self.assertNotIn("private-key", sanitized)
        self.assertEqual(json.loads(sanitized)["error"]["message"], "denied")

    def test_empty_content_is_rejected_explicitly(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "content is empty"):
            parse_response(
                {
                    "status": "completed",
                    "output": [
                        {
                            "type": "message",
                            "content": [{"type": "output_text", "text": "   "}],
                        }
                    ]
                },
                "deepseek-v4-flash",
            )

    def test_incomplete_response_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "status is not completed"):
            parse_response(
                {"status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"}},
                "deepseek-v4-flash",
            )


if __name__ == "__main__":
    unittest.main()
