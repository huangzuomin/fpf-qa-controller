import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from qa.geo293_gate import check_identities, check_manifest, check_paths, check_pr, decision

SPEC = json.loads((Path(__file__).parents[1] / 'qa/geo293-spec.json').read_text())


def pr():
    repo = {'full_name': SPEC['candidate_repo']}
    return {'number': 293, 'state': 'open', 'user': {'id': 10},
            'base': {'repo': repo, 'ref': 'main', 'sha': SPEC['base']},
            'head': {'repo': repo, 'sha': SPEC['head']}}


class GateTests(unittest.TestCase):
    def test_bindings_and_race(self):
        check_pr(SPEC, pr(), pr())
        for side in ('base', 'head'):
            bad = copy.deepcopy(pr())
            bad[side]['sha'] = 'f' * 40
            with self.subTest(side=side), self.assertRaises(ValueError):
                check_pr(SPEC, pr(), bad)

    def test_unauthorized_file(self):
        check_paths(SPEC['allowed_paths'], SPEC)
        with self.assertRaises(ValueError):
            check_paths(SPEC['allowed_paths'] + ['docs/PROJECT-MAP.md'], SPEC)

    def test_forged_or_missing_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'log').write_bytes(b'actual')
            check_manifest(root, {'log': hashlib.sha256(b'actual').hexdigest()})
            for item in ({}, {'log': hashlib.sha256(b'forged').hexdigest()}, {'../log': 'x'}, {'missing': 'x'}):
                with self.subTest(item=item), self.assertRaises(ValueError):
                    check_manifest(root, item)

    def test_identity_collision_and_missing(self):
        check_identities(1, 2, 3)
        for ids in ((1, 1, 3), (1, 2, 2), (1, 2, 1), (1, 2, None)):
            with self.subTest(ids=ids), self.assertRaises(ValueError):
                check_identities(*ids)

    def test_failure_or_forged_success_never_authorizes(self):
        for checks in ({'test': 'FAIL'}, {'test': 'PASS'}, {}, {'verdict': 'PASS', 'semantic': True}):
            self.assertEqual(decision(checks)['verdict'], 'BLOCKED')

    def test_end_to_end_against_real_git_and_changed_snapshot(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            repo = root / 'candidate'
            repo.mkdir()
            def git(*args):
                return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.DEVNULL).decode().strip()
            git('init')
            git('config', 'user.email', 'test@example.invalid')
            git('config', 'user.name', 'Controller test')
            (repo / 'file').write_text('base', encoding='utf-8')
            git('add', 'file')
            git('commit', '-m', 'base')
            base = git('rev-parse', 'HEAD')
            (repo / 'file').write_text('head', encoding='utf-8')
            git('commit', '-am', 'head')
            head = git('rev-parse', 'HEAD')
            spec = dict(SPEC, base=base, head=head, allowed_paths=['file'])
            snapshot = pr()
            snapshot['base']['sha'], snapshot['head']['sha'] = base, head
            for name, data in [('spec', spec), ('before', snapshot), ('after', snapshot)]:
                (root / name).write_text(json.dumps(data), encoding='utf-8')
            script = Path(__file__).parents[1] / 'qa/geo293_gate.py'
            command = [sys.executable, str(script), '--candidate', str(repo), '--spec', str(root / 'spec'),
                       '--before', str(root / 'before'), '--after', str(root / 'after'), '--output', str(root / 'result')]
            subprocess.run(command, check=True)
            result = json.loads((root / 'result').read_text())
            self.assertEqual(result['verdict'], 'BLOCKED')
            self.assertEqual(result['checks']['checkout_ancestry_paths'], 'PASS')
            snapshot['head']['sha'] = 'f' * 40
            (root / 'after').write_text(json.dumps(snapshot), encoding='utf-8')
            subprocess.run(command, check=True)
            result = json.loads((root / 'result').read_text())
            self.assertEqual(result['verdict'], 'BLOCKED')
            self.assertIn('FAIL', result['checks']['admission'])


if __name__ == '__main__':
    unittest.main()
