"""Controller-owned synthetic probes; run candidate only inside offline container.

This is behavioral evidence, not a semantic approval or provenance attestation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import yaml

HEAD = '560e0f70db9c5f68c9d51b3d2ae3dfa4c7e7965c'
BASE = 'b95b9478c04a32f8a57267c89dc453a6f8829d17'
IDS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 29, 30, 31, 32]
CASES = ('valid', 'empty', 'missing', 'hash', 'nonzero', 'identity',
         'composite', 'head_race', 'base_race', 'artifact_origin', 'failed_result')


def command(*args, cwd=None, env=None):
    return subprocess.run(args, cwd=cwd, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True, timeout=120).stdout.decode().strip()


def extract_script(candidate):
    path = candidate / '.github/workflows/fpf-independent-qa.yml'
    workflow = yaml.load(path.read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
    steps = [s for s in workflow['jobs']['review']['steps']
             if s.get('name') == 'Validate evidence and submit exact-SHA App review']
    if len(steps) != 1:
        raise ValueError('unexpected review step')
    run = steps[0]['run']
    prefix, suffix = "python - <<'PY'\n", '\nPY'
    if run.count(prefix) != 1 or not run.rstrip().endswith(suffix):
        raise ValueError('unexpected review script wrapper')
    return run.split(prefix, 1)[1].rsplit(suffix, 1)[0]


def git(repo, *args):
    return command('git', '-C', str(repo), *args)


def fixture(root, case, candidate, script, fake_bin):
    candidate_repo, trusted, artifact = (root / 'candidate-objects', root / 'trusted', root / 'qa-artifact')
    command('git', 'init', '-q', str(candidate_repo))
    git(candidate_repo, 'config', 'user.email', 'fixture@example.invalid')
    git(candidate_repo, 'config', 'user.name', 'fixture')
    project_map = candidate_repo / 'docs/PROJECT-MAP.md'
    project_map.parent.mkdir()
    project_map.write_text('base\n')
    git(candidate_repo, 'add', '.')
    git(candidate_repo, 'commit', '-qm', 'base')
    base = git(candidate_repo, 'rev-parse', 'HEAD')
    project_map.write_text('update\n')
    git(candidate_repo, 'commit', '-qam', 'update')
    head = git(candidate_repo, 'rev-parse', 'HEAD')
    command('git', 'clone', '-q', '--no-hardlinks', '--no-checkout', str(candidate), str(trusted))
    git(trusted, 'checkout', '-q', '--detach', BASE)
    artifact.mkdir()
    items = []
    for number in IDS:
        eid = f'EVID-{number:02d}'
        header = {'task_id': 'CONTROLLER-TEST', 'tested_sha': head, 'evid_id': eid,
                  'timed_out': False, 'command': 'synthetic',
                  'exit_code': 1 if case == 'nonzero' and number == 1 else 0}
        data = (json.dumps(header) + '\nfixture\n').encode()
        filename = eid + '.log'
        (artifact / filename).write_bytes(data)
        items.append({'id': eid, 'status': 'PASS', 'path': filename,
                      'sha256': hashlib.sha256(data).hexdigest()})
    if case == 'empty':
        items = []
    elif case == 'missing':
        items.pop()
    elif case == 'hash':
        items[0]['sha256'] = '0' * 64
    manifest = {'manifest_version': 1, 'verdict': 'FAIL' if case == 'failed_result' else 'PASS',
                'diagnostic_mode': False, 'task_id': 'CONTROLLER-TEST', 'tested_sha': head,
                'profile': 'Library', 'items': items}
    (artifact / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    card = {'kind': 'MAP_UPDATE', 'task_id': 'CONTROLLER-TEST', 'project_id': 'GEO-CORE',
            'code_merged_sha': base, 'project_map': 'docs/PROJECT-MAP.md',
            'changed_files': ['docs/PROJECT-MAP.md'], 'base_ref': 'main'}
    body = '```yaml\n' + yaml.safe_dump(card) + '```'
    if case == 'composite':
        body += '\n```yaml\nkind: POLICY_CHANGE\n```'
    bot = 'fixture-qa[bot]'
    pr = {'state': 'open', 'head': {'sha': head}, 'base': {'ref': 'main', 'sha': base},
          'user': {'login': bot if case == 'identity' else 'fixture-author'}, 'body': body}
    second = json.loads(json.dumps(pr))
    if case == 'head_race':
        second['head']['sha'] = 'f' * 40
    if case == 'base_race':
        second['base']['sha'] = 'e' * 40
    responses = {'pr_first': pr, 'pr_second': second,
                 'run': {'event': 'workflow_dispatch', 'head_sha': BASE, 'head_branch': 'main',
                         'actor': {'login': bot}, 'triggering_actor': {'login': bot}},
                 'artifact': {'workflow_run': {'id': 999 if case == 'artifact_origin' else 123},
                              'expired': False, 'name': 'fpf-qa-' + head}}
    (root / 'responses.json').write_text(json.dumps(responses))
    script_file = root / 'candidate-script.py'
    script_file.write_text(script, encoding='utf-8')
    env = {'PATH': f'{fake_bin}:/usr/local/bin:/usr/bin:/bin', 'HOME': str(root),
           'PYTHONPATH': str(trusted / '.fpf/vendor'), 'PYTHONDONTWRITEBYTECODE': '1',
           'FAKE_GH_ROOT': str(root), 'GITHUB_REPOSITORY': 'huangzuomin/geo-service-core',
           'GITHUB_RUN_ID': '123', 'GITHUB_SHA': BASE, 'GITHUB_REF': 'refs/heads/main',
           'FPF_APP_SLUG': 'fixture-qa', 'FPF_EXPECTED_BOT_LOGIN': bot,
           'FPF_SHA': head, 'FPF_PR': '291', 'FPF_TASK': 'CONTROLLER-TEST',
           'FPF_PROFILE': 'Library', 'FPF_DIAGNOSTIC': 'false', 'FPF_ARTIFACT_ID': '456'}
    run = subprocess.run([sys.executable, str(script_file)], cwd=root, env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    write = root / 'write.json'
    if case == 'valid':
        if run.returncode != 0 or not write.is_file():
            return False
        payload = json.loads(write.read_text())
        return payload.get('event') == 'APPROVE' and payload.get('commit_id') == head
    return run.returncode != 0 and not write.exists()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidate', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = {'verdict': 'BLOCKED', 'cases': {}, 'behavioral_evidence': 'NOT_RUN'}
    try:
        if git(args.candidate, 'rev-parse', 'HEAD') != HEAD:
            raise ValueError('candidate binding')
        stored = subprocess.check_output(['git', '-C', str(args.candidate), 'show',
                                          HEAD + ':.github/workflows/fpf-independent-qa.yml'],
                                         stderr=subprocess.DEVNULL, timeout=30)
        if stored != (args.candidate / '.github/workflows/fpf-independent-qa.yml').read_bytes():
            raise ValueError('candidate workflow differs from pinned object')
        script = extract_script(args.candidate)
        fake_bin = Path(__file__).resolve().parent / 'bin'
        for case in CASES:
            with tempfile.TemporaryDirectory() as name:
                result['cases'][case] = 'PASS' if fixture(Path(name), case, args.candidate, script, fake_bin) else 'FAIL'
        result['behavioral_evidence'] = 'COMPLETE'
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, yaml.YAMLError):
        result['behavioral_evidence'] = 'ERROR'
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return 0 if result['behavioral_evidence'] == 'COMPLETE' and all(x == 'PASS' for x in result['cases'].values()) else 1


if __name__ == '__main__':
    sys.exit(main())
