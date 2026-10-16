import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest.mock import patch

from vulngym_agent.qwen_budget import reserve, settle
from vulngym_agent.qwen_provider import call_qwen


class QwenBudgetTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'budget.json'
        self.environment = patch.dict(os.environ, {
            'VULNGYM_QWEN_BUDGET_FILE': str(self.path),
            'VULNGYM_QWEN_CALL_LIMIT': '2',
            'VULNGYM_QWEN_TOTAL_TOKEN_LIMIT': '20000',
            'VULNGYM_QWEN_COST_LIMIT_CNY': '0.6',
            'VULNGYM_QWEN_MAX_TOKENS': '100'})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.payload = {'model': 'qwen3.8-flash', 'enable_thinking': False,
                        'max_tokens': 100, 'messages': [{'role': 'user', 'content': 'test'}]}
        self.base = 'https://dashscope.aliyuncs.com/compatible-mode/v1'

    def ledger(self):
        return json.loads(self.path.read_text())

    def test_call_limit_blocks_before_http(self):
        for unused in range(2):
            reserve(self.payload, self.base)
        with patch('urllib.request.urlopen') as http:
            with self.assertRaisesRegex(RuntimeError, 'call budget'):
                call_qwen({'output_schema': {'type': 'object'}}, api_key='local-test-secret',
                          model='qwen3.8-flash', enabled=True)
            http.assert_not_called()
        self.assertNotIn('local-test-secret', self.path.read_text())

    def test_oversized_input_is_blocked_before_http(self):
        with patch('urllib.request.urlopen') as http:
            with self.assertRaisesRegex(RuntimeError, 'token budget'):
                call_qwen({'output_schema': {'type': 'object'}, 'data': 'a' * 22000},
                          api_key='test', model='qwen3.8-flash', enabled=True)
            http.assert_not_called()

    def test_unknown_usage_keeps_full_reservation(self):
        ticket = reserve(self.payload, self.base)
        before = self.ledger()['calls'][0]['tokens']
        settle(ticket, None)
        row = self.ledger()['calls'][0]
        self.assertEqual(row['tokens'], before)
        self.assertEqual(row['status'], 'usage_unknown_reservation_retained')

    def test_usage_replaces_reservation_with_undiscounted_cost(self):
        ticket = reserve(self.payload, self.base)
        settle(ticket, {'usage': {'prompt_tokens': 1000, 'completion_tokens': 100}})
        row = self.ledger()['calls'][0]
        self.assertEqual(row['tokens'], 1100)
        self.assertAlmostEqual(row['estimated_cny'], 0.00107)

    def test_parallel_reservations_cannot_bypass_call_limit(self):
        os.environ['VULNGYM_QWEN_CALL_LIMIT'] = '1'
        def attempt(unused):
            try:
                return bool(reserve(self.payload, self.base))
            except RuntimeError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(attempt, range(2))), 1)
        self.assertEqual(len(self.ledger()['calls']), 1)

    def test_other_prices_and_thinking_are_blocked(self):
        for payload, base in (({**self.payload, 'model': 'qwen3.7-plus'}, self.base),
                              (self.payload, 'https://example.invalid'),
                              ({**self.payload, 'enable_thinking': True}, self.base)):
            with self.assertRaises(RuntimeError):
                reserve(payload, base)


if __name__ == '__main__':
    unittest.main()
