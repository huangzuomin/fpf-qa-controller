import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from qa.geo293_gate import check_identities, check_manifest, check_paths, check_pr, decision
from qa.geo293_projection import project

SPEC = json.loads((Path(__file__).parents[1] / 'qa/geo293-spec.json').read_text())


def pr():
    repo = {'full_name': SPEC['candidate_repo']}
    return {'number': 293, 'state': 'open', 'user': {'id': 10},
            'base': {'repo': repo, 'ref': 'main', 'sha': SPEC['base']},
            'head': {'repo': repo, 'sha': SPEC['head']}}


class GateTests(unittest.TestCase):
    def test_projection_never_copies_private_canaries(self):
        canary = 'PRIVATE_CANARY_8fd47e'
        data = pr()
        data.update({'body': canary, 'title': canary, 'diff_url': canary,
                     'files': [{'path': canary, 'patch': canary}], 'extra': {'secret': canary}})
        data['base']['private_extra'] = canary
        data['head']['repo']['private_extra'] = canary
        projected = project(data)
        self.assertNotIn(canary, json.dumps(projected))
        self.assertEqual(set(projected), {'number', 'state', 'user', 'base', 'head'})
        self.assertEqual(set(projected['base']), {'ref', 'sha', 'repo'})
        self.assertEqual(set(projected['head']), {'sha', 'repo'})
        self.assertEqual(set(projected['base']['repo']), {'full_name'})
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / 'projection.json'
            script = Path(__file__).parents[1] / 'qa/geo293_projection.py'
            proc = subprocess.run([sys.executable, str(script), str(out)], input=json.dumps(data),
                                  text=True, capture_output=True, check=True)
            self.assertNotIn(canary, out.read_text(encoding='utf-8') + proc.stdout + proc.stderr)
            bad = subprocess.run([sys.executable, str(script), str(out)], input=canary,
                                 text=True, capture_output=True)
            self.assertNotEqual(bad.returncode, 0)
            self.assertNotIn(canary, bad.stdout + bad.stderr)

    def test_geo_workflow_has_no_artifact_or_attestation_sink(self):
        workflow = (Path(__file__).parents[1] / '.github/workflows/geo293-observation.yml').read_text(encoding='utf-8')
        for forbidden in ('upload-artifact', 'download-artifact', 'actions/attest', 'attestation verify',
                          'before.json >', 'cat "$RUNNER_TEMP', 'tee ', 'gh release'):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)
        self.assertEqual(workflow.count('qa/geo293_projection.py'), 2)
        self.assertIn('2>/dev/null | python3 qa/geo293_projection.py', workflow)
        self.assertEqual(re.findall(r'^\s*-?\s*uses:\s*(\S+)', workflow, re.MULTILINE),
                         ['actions/checkout@11d5960a326750d5838078e36cf38b85af677262'])
        self.assertEqual(workflow.count('gh api '), 3)

    def test_bindings_and_race(self):
        check_pr(SPEC, pr(), pr())
        for side in ('base', 'head'):
            bad = copy.deepcopy(pr())
            bad[side]['sha'] = 'f' * 40
            with self.subTest(side=side), self.assertRaises(ValueError):
                check_pr(SPEC, pr(), bad)

    def test_unauthorized_file(self):
        path_spec = {'allowed_path_sha256': [hashlib.sha256(b'example').hexdigest()]}
        check_paths(['example'], path_spec)
        with self.assertRaises(ValueError):
            check_paths(['example', 'unexpected'], path_spec)

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
            spec = dict(SPEC, base=base, head=head,
                        allowed_path_sha256=[hashlib.sha256(b'file').hexdigest()])
            snapshot = pr()
            snapshot['base']['sha'], snapshot['head']['sha'] = base, head
            for name, data in [('spec', spec), ('before', snapshot), ('after', snapshot)]:
                (root / name).write_text(json.dumps(data), encoding='utf-8')
            script = Path(__file__).parents[1] / 'qa/geo293_gate.py'
            command = [sys.executable, str(script), '--candidate', str(repo), '--spec', str(root / 'spec'),
                       '--before', str(root / 'before'), '--after', str(root / 'after'), '--output', str(root / 'result')]
            proc = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0)
            result = json.loads((root / 'result').read_text())
            self.assertEqual(result['verdict'], 'BLOCKED')
            self.assertEqual(result['checks']['admission'], 'PASS')
            self.assertEqual(result['checks']['checkout_ancestry_paths'], 'PASS')
            snapshot['head']['sha'] = 'PRIVATE_SHA_CANARY'
            (root / 'after').write_text(json.dumps(snapshot), encoding='utf-8')
            proc = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)
            result = json.loads((root / 'result').read_text())
            self.assertEqual(result['verdict'], 'BLOCKED')
            self.assertEqual(result['checks']['admission'], 'FAIL')
            self.assertNotIn('PRIVATE_SHA_CANARY', json.dumps(result) + proc.stdout + proc.stderr)
            # A private unexpected file name must never enter the error result.
            snapshot['head']['sha'] = head
            (root / 'after').write_text(json.dumps(snapshot), encoding='utf-8')
            (repo / 'PRIVATE_PATH_CANARY').write_text('PRIVATE_SOURCE_CANARY', encoding='utf-8')
            git('add', 'PRIVATE_PATH_CANARY')
            git('commit', '-m', 'private')
            new_head = git('rev-parse', 'HEAD')
            spec['head'] = new_head
            snapshot['head']['sha'] = new_head
            for name, data in [('spec', spec), ('before', snapshot), ('after', snapshot)]:
                (root / name).write_text(json.dumps(data), encoding='utf-8')
            proc = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)
            published = (root / 'result').read_text(encoding='utf-8') + proc.stdout + proc.stderr
            self.assertNotIn('PRIVATE_PATH_CANARY', published)
            self.assertNotIn('PRIVATE_SOURCE_CANARY', published)
            self.assertEqual(json.loads(published)['checks']['admission'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
