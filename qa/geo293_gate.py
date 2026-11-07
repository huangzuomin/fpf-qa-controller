"""Read-only admission checks. These checks never authorize a review."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_pr(spec, before, after):
    for pr in (before, after):
        require(pr['number'] == spec['pr'] and pr['state'] == 'open', 'PR identity/state')
        require(pr['base']['repo']['full_name'] == spec['candidate_repo'], 'base repository')
        require(pr['head']['repo']['full_name'] == spec['candidate_repo'], 'head repository')
        require(pr['base']['ref'] == 'main', 'base branch')
        require(pr['base']['sha'] == spec['base'] and pr['head']['sha'] == spec['head'], 'SHA mismatch or race')
    require(before['user']['id'] == after['user']['id'], 'author identity changed')


def check_paths(actual, spec):
    require(len(actual) == len(set(actual)), 'duplicate path')
    actual_hashes = {hashlib.sha256(path.encode('utf-8')).hexdigest() for path in actual}
    require(actual_hashes == set(spec['allowed_path_sha256']), 'changed path outside exact allowlist')


def check_identities(author, qa, gov):
    ids = (author, qa, gov)
    require(all(isinstance(i, int) and not isinstance(i, bool) and i > 0 for i in ids), 'missing identity')
    require(len(set(ids)) == 3, 'identity collision')


def check_manifest(root, manifest):
    require(isinstance(manifest, dict) and bool(manifest), 'empty evidence')
    for name, expected in manifest.items():
        path = Path(name)
        require(not path.is_absolute() and '..' not in path.parts and len(path.parts) == 1, 'unsafe evidence path')
        file = root / path
        require(file.is_file() and not file.is_symlink(), 'missing evidence')
        require(hashlib.sha256(file.read_bytes()).hexdigest() == expected, 'evidence hash mismatch')


def decision(checks):
    # Semantic authorization has not been established. No input can turn this into PASS.
    return {'verdict': 'BLOCKED', 'checks': checks,
            'reason': 'Independent semantic authorization and candidate behavior tests are not established'}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--candidate', type=Path, required=True)
    p.add_argument('--spec', type=Path, required=True)
    p.add_argument('--before', type=Path, required=True)
    p.add_argument('--after', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    checks = {}
    try:
        spec = json.loads(args.spec.read_text(encoding='utf-8'))
        before = json.loads(args.before.read_text(encoding='utf-8'))
        after = json.loads(args.after.read_text(encoding='utf-8'))
        check_pr(spec, before, after)
        checks['pr_binding'] = 'PASS'
        def git(*argv):
            return subprocess.check_output(['git', '-C', str(args.candidate), *argv], stderr=subprocess.DEVNULL)
        require(git('rev-parse', 'HEAD').decode().strip() == spec['head'], 'checkout SHA')
        subprocess.run(['git', '-C', str(args.candidate), 'merge-base', '--is-ancestor', spec['base'], spec['head']], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        paths = git('diff', '--no-renames', '--name-only', '-z', spec['base'] + '...' + spec['head']).decode('utf-8').split('\0')
        check_paths(paths[:-1], spec)
        checks['checkout_ancestry_paths'] = 'PASS'
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, subprocess.SubprocessError):
        checks['admission'] = 'FAIL'
    args.output.write_text(json.dumps(decision(checks), indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
