"""Aggregate diagnostics: no failed endpoint addresses are persisted."""
from collections import Counter

CAUSES = {'connection_refused', 'connect_timeout', 'tls_timeout', 'http_timeout',
          'tls_error', 'http_error', 'connect_error'}

def classify(result):
    if result.get('status') == 'hit':
        primary = 'hit'
    elif result.get('error_kind') in CAUSES:
        primary = result['error_kind']
    elif result.get('status') == 'open_not_cf':
        primary = 'open_not_cf'
    else:
        primary = 'unknown_error'
    counts = Counter({primary: 1})
    if result.get('status') == 'hit':
        if result.get('verification') == 'error':
            counts['verify_' + (result.get('verify_error') or 'unknown_error')] += 1
        elif result.get('verification') == 'not_confirmed':
            counts['verify_not_confirmed'] += 1
        elif result.get('evidence') == 'dual_verified':
            counts['verify_confirmed'] += 1
    return counts
