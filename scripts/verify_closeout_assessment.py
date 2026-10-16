"""One final regression, reusing the original strict shared request budget."""
import json
import os
from pathlib import Path
import sys

import evaluate_holdout_v2 as bench


def main():
    root = Path(sys.argv[1]).resolve()
    output = root / 'final-182'
    if (output / 'focused').exists():
        raise ValueError('Use a fresh final directory')
    output.mkdir(exist_ok=True)
    os.environ.update({
        'VULNGYM_QWEN_BUDGET_FILE': str(root / 'budget.json'),
        'VULNGYM_QWEN_TOTAL_TOKEN_LIMIT': '200000',
        'VULNGYM_QWEN_CALL_LIMIT': '60',
        'VULNGYM_QWEN_COST_LIMIT_CNY': '0.6',
        'VULNGYM_QWEN_MODEL': 'qwen3.8-flash',
        'VULNGYM_QWEN_BASE_URL': 'https://dashscope.aliyuncs.com/compatible-mode/v1',
        'VULNGYM_QWEN_ENABLE_THINKING': 'false',
        'VULNGYM_QWEN_MAX_TOKENS': '1024',
        'VULNGYM_QWEN_TIMEOUT_SECONDS': '90',
    })
    previous = json.loads((root / 'known-failures/manifest.json').read_text())
    cases = [row for row in previous['cases'] if row['request']['case_id'] == 'hono-02']
    bench.build = lambda: {'version': 'final-assessment-contract-regression',
        'cases': cases, 'reports': [], 'limitations': [
            'One known failure; latest prompt has not rerun the full coverage batch.',
            'Do not pool results across prompt versions or claim independent accuracy.']}
    bench.freeze(output / 'focused')
    bench.run(output / 'focused')
    ledger = json.loads((root / 'budget.json').read_text())
    summary = {'actual_http_requests': len(ledger['calls']),
        'returned_tokens': sum(row['tokens'] for row in ledger['calls'] if row['status'] == 'returned'),
        'estimated_cny': sum(row['estimated_cny'] for row in ledger['calls']),
        'unknown_usage_reservations': sum(row['status'] != 'returned' for row in ledger['calls']),
        'limits': ledger['limits'], 'independent_accuracy_claim': False}
    bench.save(root / 'budget-summary.json', summary)
    print(json.dumps({'budget': summary}), flush=True)


if __name__ == '__main__':
    main()
