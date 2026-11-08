"""Project untrusted PR API responses for local admission only, never for publication."""
import json
import sys
from pathlib import Path


def project(pr):
    # Construct from scratch: no title, body, URLs, labels, comments or extra fields.
    if not isinstance(pr, dict):
        raise ValueError('invalid PR response')
    try:
        number, state, author = pr['number'], pr['state'], pr['user']['id']
        base, head = pr['base'], pr['head']
        values = (state, base['ref'], base['sha'], head['sha'],
                  base['repo']['full_name'], head['repo']['full_name'])
        if type(number) is not int or type(author) is not int or not all(type(x) is str for x in values):
            raise ValueError('invalid PR response')
        return {
            'number': number, 'state': state, 'user': {'id': author},
            'base': {'ref': values[1], 'sha': values[2], 'repo': {'full_name': values[4]}},
            'head': {'sha': values[3], 'repo': {'full_name': values[5]}},
        }
    except (KeyError, TypeError):
        raise ValueError('invalid PR response') from None


def main():
    try:
        data = json.load(sys.stdin)
        result = project(data)
        Path(sys.argv[1]).write_text(json.dumps(result) + '\n', encoding='utf-8')
    except (ValueError, OSError, IndexError, RecursionError):
        # Do not echo an untrusted field, exception or input.
        print('PR_PROJECTION_FAILED', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
