"""Shared, opt-in request budget for bounded Beijing Flash acceptance runs."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
from uuid import uuid4


@contextmanager
def _ledger(path):
    import fcntl
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a+', encoding='utf-8') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        handle.seek(0)
        raw = handle.read()
        value = json.loads(raw) if raw else {'version': 1, 'calls': []}
        yield value
        handle.seek(0)
        handle.truncate()
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.flush()
        os.fsync(handle.fileno())


def reserve(payload, base_url):
    path = os.environ.get('VULNGYM_QWEN_BUDGET_FILE')
    if not path:
        return None
    if payload['model'] != 'qwen3.8-flash' or base_url.rstrip('/') != 'https://dashscope.aliyuncs.com/compatible-mode/v1':
        raise RuntimeError('Budgeted acceptance permits only Beijing qwen3.8-flash')
    if payload.get('enable_thinking'):
        raise RuntimeError('Budgeted acceptance requires non-thinking mode')
    token_limit = int(os.environ.get('VULNGYM_QWEN_TOTAL_TOKEN_LIMIT', '200000'))
    call_limit = int(os.environ.get('VULNGYM_QWEN_CALL_LIMIT', '60'))
    cost_limit = float(os.environ.get('VULNGYM_QWEN_COST_LIMIT_CNY', '0.6'))
    if token_limit <= 0 or call_limit <= 0 or not 0 < cost_limit <= 0.6:
        raise RuntimeError('Invalid acceptance budget')
    # UTF-8 byte count upper-bounds ordinary text tokenization. Include schema
    # bytes and 1024 tokens of protocol headroom rather than trusting an average.
    input_bound = len(json.dumps(payload, ensure_ascii=False).encode('utf-8')) + 1024
    output_bound = payload['max_tokens']
    if type(output_bound) is not int or output_bound <= 0:
        raise RuntimeError('A finite output cap is required')
    row = {'id': uuid4().hex, 'status': 'reserved',
           'tokens': input_bound + output_bound,
           'estimated_cny': (input_bound * 0.8 + output_bound * 2.7) / 1000000}
    with _ledger(path) as value:
        if len(value['calls']) >= call_limit:
            raise RuntimeError('Acceptance call budget reached; no HTTP request sent')
        if sum(item['tokens'] for item in value['calls']) + row['tokens'] > token_limit:
            raise RuntimeError('Acceptance token budget reached; no HTTP request sent')
        if sum(item['estimated_cny'] for item in value['calls']) + row['estimated_cny'] > cost_limit:
            raise RuntimeError('Acceptance cost budget reached; no HTTP request sent')
        value['limits'] = {'tokens': token_limit, 'calls': call_limit, 'estimated_cny': cost_limit}
        value['calls'].append(row)
    return path, row['id']


def settle(ticket, response):
    if ticket is None:
        return
    path, identifier = ticket
    usage = response.get('usage', {}) if isinstance(response, dict) else {}
    incoming, outgoing = usage.get('prompt_tokens'), usage.get('completion_tokens')
    known = all(type(item) is int and item >= 0 for item in (incoming, outgoing))
    with _ledger(path) as value:
        row = next(item for item in value['calls'] if item['id'] == identifier)
        if known:
            row.update(status='returned', input_tokens=incoming, output_tokens=outgoing,
                       tokens=incoming + outgoing,
                       estimated_cny=(incoming * 0.8 + outgoing * 2.7) / 1000000)
        else:
            # A timeout or response without usage may still be billable. Never
            # release its reservation or issue an automatic retry.
            row['status'] = 'usage_unknown_reservation_retained'
