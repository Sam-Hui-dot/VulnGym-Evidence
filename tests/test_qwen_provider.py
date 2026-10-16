from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from vulngym_agent.qwen_provider import (
    _sanitize_error_body,
    build_payload,
    call_qwen,
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


class QwenProviderTests(unittest.TestCase):
    def test_payload_requests_strict_structured_output(self) -> None:
        payload = build_payload(semantic_request(), "qwen3.8-flash")
        self.assertEqual(payload["model"], "qwen3.8-flash")
        self.assertFalse(payload["enable_thinking"])
        self.assertTrue(payload["response_format"]["json_schema"]["strict"])
        self.assertNotIn("output_schema", json.loads(payload["messages"][1]["content"]))

    def test_parses_result_and_usage_metadata(self) -> None:
        parsed = parse_response(
            {
                "id": "generation-1",
                "model": "qwen3.8-flash",
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": '{"entry_id":"entry-1"}'},
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            },
            "qwen3.8-flash",
        )
        self.assertEqual(parsed["result"], {"entry_id": "entry-1"})
        self.assertEqual(parsed["metadata"]["transport"], "qwen_chat_completions")
        self.assertEqual(parsed["metadata"]["usage"]["total_tokens"], 15)
        self.assertEqual(parsed["metadata"]["usage"]["input_tokens"], 10)
        self.assertEqual(parsed["metadata"]["usage"]["output_tokens"], 5)

    def test_call_sends_key_but_never_returns_it(self) -> None:
        response = {
            "choices": [
                {"finish_reason": "stop", "message": {"content": '{"entry_id":"entry-1"}'}}
            ]
        }
        captured = {}

        def fake_urlopen(request, timeout):
            captured["authorization"] = request.headers["Authorization"]
            captured["url"] = request.full_url
            captured["timeout"] = timeout
            return FakeHttpResponse(response)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = call_qwen(
                semantic_request(),
                api_key="test-secret",
                model="qwen3.8-flash",
                enabled=True,
                timeout_seconds=30,
            )
        self.assertEqual(captured["authorization"], "Bearer test-secret")
        self.assertEqual(
            captured["url"],
            "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
        )
        self.assertEqual(captured["timeout"], 30)
        self.assertNotIn("test-secret", json.dumps(result))

    def test_disabled_fails_before_network(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "Qwen calls are disabled"):
            call_qwen(
                semantic_request(),
                api_key="test-secret",
                model="qwen3.8-flash",
                enabled=False,
            )

    def test_missing_key_fails_before_network(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "DASHSCOPE_API_KEY is not set"):
            call_qwen(
                semantic_request(),
                api_key="",
                model="qwen3.8-flash",
                enabled=True,
            )

    def test_error_body_removes_private_identifiers(self) -> None:
        sanitized = _sanitize_error_body(
            '{"error":{"message":"denied"},"user_id":"private-user","api_key":"private-key"}'
        )
        self.assertNotIn("private-user", sanitized)
        self.assertNotIn("private-key", sanitized)
        self.assertEqual(json.loads(sanitized)["error"]["message"], "denied")


if __name__ == "__main__":
    unittest.main()
