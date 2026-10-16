"""Real local HTTP demo and one focused regression within the shared budget."""
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import re
import socket
import sys
import time
from urllib.request import Request, urlopen

import evaluate_holdout_v2 as bench
from vulngym_agent.provider import load_provider
from vulngym_evidence.server import serve_local


def main():
    root = Path(sys.argv[1]).resolve()
    output = root / 'final-181'
    if output.exists():
        raise ValueError('Use a fresh final check directory')
    output.mkdir()
    os.environ.update({
        'VULNGYM_QWEN_BUDGET_FILE': str(root / 'budget.json'),
        'VULNGYM_QWEN_TOTAL_TOKEN_LIMIT': '200000',
        'VULNGYM_QWEN_CALL_LIMIT': '60',
        'VULNGYM_QWEN_COST_LIMIT_CNY': '0.6',
        'VULNGYM_QWEN_MODEL': 'qwen3.8-flash',
        'VULNGYM_QWEN_BASE_URL': 'https://dashscope.aliyuncs.com/compatible-mode/v1',
        'VULNGYM_QWEN_ENABLE_THINKING': 'false',
        'VULNGYM_QWEN_MAX_TOKENS': '2048',
        'VULNGYM_QWEN_TIMEOUT_SECONDS': '90',
    })
    bench.load_credentials()
    previous = json.loads((root / 'known-failures/manifest.json').read_text())
    focused = [row for row in previous['cases'] if row['request']['case_id'] == 'hono-02']
    bench.build = lambda: {'version': 'focused-window-selector-regression',
        'cases': focused, 'reports': [],
        'limitations': ['Known failure after 1.8.0; does not replace that result or estimate accuracy.']}
    bench.freeze(output / 'focused')

    old = bench.ROOT / 'out/v2-validation/20261004/f370782ee2414b16b35317d2818b0250/result.json'
    request = json.loads(old.read_text())['request']
    request['case_id'] = 'closeout-demo-20261005-181'
    bench.save(output / 'confirmed-input.json', request)
    configuration = {'roots': [Path('/home/sam/rhinobird/vulngym-repos')],
        'repository': None, 'advisory_documents': [], 'use_critic': True,
        'provider': load_provider(bench.ROOT / 'configs/provider.qwen.json')}
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    context = multiprocessing.get_context('fork')
    def start():
        process = context.Process(target=serve_local, kwargs={'port': port,
            'output_dir': output / 'web', 'configuration': configuration})
        process.start()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                page = urlopen(base, timeout=1).read().decode('utf-8')
                return process, re.search(r'name="evidence-token" content="([a-f0-9]+)"', page).group(1)
            except OSError:
                time.sleep(0.1)
        process.terminate()
        process.join(3)
        raise RuntimeError('Local server did not start')
    def get(path):
        return json.loads(urlopen(base + path, timeout=5).read())
    process, token = start()
    def post(path, value):
        http = Request(base + path, data=json.dumps(value, ensure_ascii=False).encode(),
            headers={'Content-Type': 'application/json', 'X-Evidence-Token': token, 'Origin': base})
        return json.loads(urlopen(http, timeout=120).read())
    checks = {'input_confirmation': 'reused previously user-confirmed teaching input; new task, no replayed output',
              'visual_browser_test': False}
    try:
        extraction = post('/api/extract', {'report_text': request['report_text']})
        bench.save(output / 'extraction-response.json', extraction)
        checks['extraction_completed'] = True
        checks['extraction_candidates'] = len(extraction.get('candidates', []))
        checked = post('/api/validate', request)
        bench.save(output / 'validation-response.json', checked)
        saved = post('/api/inputs', request)
        downloaded = get(saved['download_url'])
        checks['input_download_matches'] = downloaded == request
        job_id = post('/api/jobs', request)['job_id']
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            job = get('/api/jobs/' + job_id)
            if job['status'] in {'completed', 'failed'}:
                break
            time.sleep(0.5)
        if job['status'] != 'completed':
            raise RuntimeError('Demo task did not complete')
        result = job['result']
        checks.update(job_id=job_id, prompt_version=result['prompt_version'],
            semantic_status=result['semantic_status'],
            verdicts=[row['verdict'] for row in result['results']],
            every_review_completed=all(row['review_status'] == 'completed' for row in result['results']),
            fresh_model_calls=len(result['model_calls']))
        exports = {}
        for name in ('result.json', 'report.md', 'report.html'):
            data = urlopen(base + '/reports/' + job_id + '/' + name, timeout=5).read()
            exports[name] = hashlib.sha256(data).hexdigest()
            (output / name).write_bytes(data)
        checks['result_export_matches'] = json.loads((output / 'result.json').read_text()) == result
        checks['export_sha256'] = exports
        process.terminate()
        process.join(3)
        process, token = start()
        restored = get('/api/jobs/' + job_id)
        checks['restored_after_server_restart'] = restored.get('restored_from_disk') is True and restored['result'] == result
        bench.save(output / 'verification.json', checks)
        print(json.dumps({'demo': checks}, ensure_ascii=False), flush=True)
    finally:
        process.terminate()
        process.join(3)
    bench.run(output / 'focused')
    ledger = json.loads((root / 'budget.json').read_text())
    summary = {'provider_attempts': len(ledger['calls']),
        'returned_tokens': sum(row['tokens'] for row in ledger['calls'] if row['status'] == 'returned'),
        'estimated_cny': sum(row['estimated_cny'] for row in ledger['calls']),
        'unknown_usage_reservations': sum(row['status'] != 'returned' for row in ledger['calls']),
        'limits': ledger['limits'], 'independent_accuracy_claim': False}
    bench.save(root / 'budget-summary.json', summary)
    print(json.dumps({'final_budget_summary': summary}), flush=True)


if __name__ == '__main__':
    main()
