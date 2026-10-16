"""One bounded closeout pass; references stay separate from provider inputs."""
import json
import os
from pathlib import Path
import sys

import evaluate_holdout_v2 as bench
from evaluate_holdout_v2_followup import regression_manifest, followup_manifest


def main():
    root = Path(sys.argv[1]).resolve()
    if root.exists():
        raise ValueError('Choose a new closeout directory; runs are never overwritten')
    root.mkdir(parents=True)
    os.environ.update({
        'VULNGYM_QWEN_BUDGET_FILE': str(root / 'budget.json'),
        'VULNGYM_QWEN_TOTAL_TOKEN_LIMIT': '200000',
        'VULNGYM_QWEN_CALL_LIMIT': '60',
        'VULNGYM_QWEN_COST_LIMIT_CNY': '0.6',
        'VULNGYM_QWEN_MODEL': 'qwen3.8-flash',
        'VULNGYM_QWEN_BASE_URL': 'https://dashscope.aliyuncs.com/compatible-mode/v1',
        'VULNGYM_QWEN_ENABLE_THINKING': 'false',
        'VULNGYM_QWEN_MAX_TOKENS': '4096',
        'VULNGYM_QWEN_TIMEOUT_SECONDS': '90',
    })
    coverage = followup_manifest()
    coverage['reports'] = coverage['reports'][:3]
    coverage['limitations'].append('Previously attempted follow-up samples, now coverage regression; not an independent blind test.')
    plans = [('known-failures', regression_manifest()), ('coverage', coverage)]
    for name, manifest in plans:
        bench.build = lambda value=manifest: value
        bench.freeze(root / name)
    # Both groups are frozen before any request. No tuning or repeat attempts
    # occurs between groups, and every provider process shares the same ledger.
    for name, manifest in plans:
        bench.run(root / name)
    ledger = json.loads((root / 'budget.json').read_text())
    summary = {'provider_attempts': len(ledger['calls']),
        'returned_tokens': sum(row['tokens'] for row in ledger['calls'] if row['status'] == 'returned'),
        'estimated_cny': sum(row['estimated_cny'] for row in ledger['calls']),
        'unknown_usage_reservations': sum(row['status'] != 'returned' for row in ledger['calls']),
        'limits': ledger['limits'], 'independent_accuracy_claim': False}
    bench.save(root / 'budget-summary.json', summary)
    print(json.dumps({'budget_summary': summary}), flush=True)


if __name__ == '__main__':
    main()
