import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import qa.geo293_adversarial as harness
from qa.geo293_adversarial import CASES, extract_script


class AdversarialHarnessTests(unittest.TestCase):
    def test_extract_only_exact_review_step(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            workflow = root / '.github/workflows/fpf-independent-qa.yml'
            workflow.parent.mkdir(parents=True)
            workflow.write_text("""jobs:
  review:
    steps:
      - name: Validate evidence and submit exact-SHA App review
        run: |
          python - <<'PY'
          print('synthetic')
          PY
""", encoding='utf-8')
            self.assertEqual(extract_script(root), "print('synthetic')")
            workflow.write_text(workflow.read_text().replace("python - <<'PY'", 'echo changed'), encoding='utf-8')
            with self.assertRaises(ValueError):
                extract_script(root)

    def test_offline_fake_github_never_talks_to_real_service(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / 'responses.json').write_text(json.dumps({
                'pr_first': {'head': 'one'}, 'pr_second': {'head': 'two'},
                'run': {}, 'artifact': {}}))
            fake = Path(__file__).parents[1] / 'qa/bin/gh'
            env = dict(os.environ, FAKE_GH_ROOT=str(root))
            cmd = [sys.executable, str(fake), 'api', 'repos/huangzuomin/geo-service-core/pulls/291']
            a = subprocess.run(cmd, env=env, capture_output=True, text=True, check=True)
            b = subprocess.run(cmd, env=env, capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(a.stdout)['head'], 'one')
            self.assertEqual(json.loads(b.stdout)['head'], 'two')
            cmd[-1] = 'repos/huangzuomin/geo-service-core/pulls/291/reviews'
            cmd.extend(['--method', 'POST', '--input', '-'])
            subprocess.run(cmd, input='{"event":"APPROVE"}', env=env, capture_output=True, text=True, check=True)
            self.assertEqual(json.loads((root / 'write.json').read_text())['event'], 'APPROVE')
            bad = subprocess.run([sys.executable, str(fake), 'api', 'unexpected'], env=env, capture_output=True)
            self.assertNotEqual(bad.returncode, 0)

    def test_required_adversarial_cases_present(self):
        self.assertEqual(set(CASES), {'valid', 'empty', 'missing', 'hash', 'nonzero', 'identity',
                                     'composite', 'head_race', 'base_race', 'artifact_origin', 'failed_result'})

    @unittest.skipUnless(os.name == 'posix', 'synthetic fake executable requires POSIX')
    def test_synthetic_probe_engine_detects_missing_base_race_guard(self):
        # This synthetic subject contains no GEO source and uses only the fake gh.
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / 'synthetic-source'
            source.mkdir()
            def git(*args):
                return subprocess.check_output(['git', '-C', str(source), *args], stderr=subprocess.DEVNULL).decode().strip()
            git('init', '-q')
            git('config', 'user.email', 'synthetic@example.invalid')
            git('config', 'user.name', 'synthetic')
            (source / 'fixture').write_text('synthetic')
            git('add', '.')
            git('commit', '-qm', 'fixture')
            base = git('rev-parse', 'HEAD')
            fake_bin = root / 'bin'
            fake_bin.mkdir()
            fake = fake_bin / 'gh'
            fake.write_text((Path(__file__).parents[1] / 'qa/bin/gh').read_text().replace(
                '#!/usr/local/bin/python3', '#!' + sys.executable), encoding='utf-8')
            fake.chmod(0o755)
            script = """
import json, subprocess
from pathlib import Path
def api(path, data=None):
    args = ['gh', 'api', 'repos/huangzuomin/geo-service-core/' + path]
    if data is not None: args += ['--method', 'POST', '--input', '-']
    return json.loads(subprocess.run(args, input=json.dumps(data) if data else None, capture_output=True, text=True, check=True).stdout)
manifest = json.loads(Path('qa-artifact/manifest.json').read_text())
first = api('pulls/291')
second = api('pulls/291')
if not manifest['items'] or first['head'] != second['head'] or first['base'] != second['base']: raise SystemExit(1)
api('pulls/291/reviews', {'event':'APPROVE', 'commit_id':first['head']['sha']})
"""
            with patch.object(harness, 'BASE', base):
                observed = []
                original_run = subprocess.run
                def record_synthetic(*args, **kwargs):
                    result = original_run(*args, **kwargs)
                    if len(args[0]) > 1 and str(args[0][1]).endswith('candidate-script.py'):
                        observed.append(result.stderr.decode(errors='replace'))
                    return result
                for case in ('valid', 'empty', 'head_race', 'base_race'):
                    work = root / case
                    work.mkdir()
                    with patch.object(harness.subprocess, 'run', side_effect=record_synthetic):
                        passed = harness.fixture(work, case, source, script, fake_bin)
                    self.assertTrue(passed, case + ': ' + (observed[-1] if observed else 'no synthetic process'))
                work = root / 'mutant'
                work.mkdir()
                mutant = script.replace(" or first['base'] != second['base']", '')
                self.assertFalse(harness.fixture(work, 'base_race', source, mutant, fake_bin))


if __name__ == '__main__':
    unittest.main()
