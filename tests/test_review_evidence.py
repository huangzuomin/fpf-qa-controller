import base64
import copy
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from qa.review_evidence import canonical, verify

OPENSSL = os.environ.get('TEST_OPENSSL', 'openssl')
NOW = datetime(2026, 11, 8, 12, tzinfo=timezone.utc)


class SignedEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        cls.keys, cls.policy = {}, {}
        for role, identity in [('host', 2), ('semantic', 3)]:
            private, public = root / (role + '.key'), root / (role + '.pub')
            subprocess.run([OPENSSL, 'genpkey', '-algorithm', 'ED25519', '-out', str(private)], check=True, capture_output=True)
            subprocess.run([OPENSSL, 'pkey', '-in', str(private), '-pubout', '-out', str(public)], check=True, capture_output=True)
            der = subprocess.run([OPENSSL, 'pkey', '-pubin', '-in', str(public), '-outform', 'DER'], check=True, capture_output=True).stdout
            cls.keys[role] = private
            cls.policy[role] = {'identity': identity, 'public_key_pem': public.read_text(), 'key_sha256': hashlib.sha256(der).hexdigest()}
        cls.expected = {'controller_repo': 'huangzuomin/fpf-qa-controller', 'controller_sha': 'a'*40,
                        'candidate_repo': 'huangzuomin/geo-service-core', 'pr': 293,
                        'head': 'b'*40, 'base': 'c'*40, 'task': 'task_1'}
        cls.ids = {'author': 1, 'host': 2, 'semantic': 3, 'bot': 4}
        cls.evidence = {'host': b'independent test evidence', 'semantic': b'independent reviewer findings'}
        cls.envelope = {}
        for role in ('host', 'semantic'):
            statement = {'version': 1, 'role': role, 'identity': cls.ids[role], 'binding': cls.expected.copy(),
                         'issued_at': '2026-11-08T11:00:00Z', 'expires_at': '2026-11-08T13:00:00Z',
                         'result': 'PASS', 'evidence_sha256': hashlib.sha256(cls.evidence[role]).hexdigest()}
            data, signature = root / (role + '.data'), root / (role + '.sig')
            data.write_bytes(canonical(statement))
            subprocess.run([OPENSSL, 'pkeyutl', '-sign', '-inkey', str(cls.keys[role]), '-rawin', '-in', str(data), '-out', str(signature)], check=True, capture_output=True)
            cls.envelope[role] = {'statement': statement, 'signature': base64.b64encode(signature.read_bytes()).decode()}

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def call(self, policy=None, envelope=None, evidence=None, expected=None, identities=None, now=NOW):
        return verify(policy if policy is not None else self.policy, envelope if envelope is not None else self.envelope,
                      evidence if evidence is not None else self.evidence, expected if expected is not None else self.expected,
                      identities if identities is not None else self.ids, now, OPENSSL)

    def test_valid_signatures_only_verify_inputs(self):
        self.assertEqual(self.call(), 'VERIFIED_INPUTS')

    def test_binding_drift_for_every_binding(self):
        for field in self.expected:
            altered = copy.deepcopy(self.expected)
            altered[field] = 294 if field == 'pr' else 'd'*40 if field in ('head', 'base', 'controller_sha') else 'different'
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.call(expected=altered)

    def test_signature_forgery_failure_empty_and_wrong_evidence(self):
        cases = []
        for role in ('host', 'semantic'):
            for field, value in [('result', 'FAIL'), ('identity', 99), ('role', 'other'), ('evidence_sha256', '0'*64)]:
                altered = copy.deepcopy(self.envelope)
                altered[role]['statement'][field] = value
                cases.append(altered)
            altered = copy.deepcopy(self.envelope)
            altered[role]['signature'] = base64.b64encode(b'x'*64).decode()
            cases.append(altered)
        for altered in cases:
            with self.assertRaises(ValueError):
                self.call(envelope=altered)
        for evidence in ({}, {'host': b'', 'semantic': b'x'}, {'host': b'wrong', 'semantic': self.evidence['semantic']}):
            with self.assertRaises(ValueError):
                self.call(evidence=evidence)

    def test_valid_signature_on_failed_semantic_review_is_rejected(self):
        altered = copy.deepcopy(self.envelope)
        altered['semantic']['statement']['result'] = 'FAIL'
        with tempfile.TemporaryDirectory() as temp:
            data, signature = Path(temp) / 'data', Path(temp) / 'sig'
            data.write_bytes(canonical(altered['semantic']['statement']))
            subprocess.run([OPENSSL, 'pkeyutl', '-sign', '-inkey', str(self.keys['semantic']),
                            '-rawin', '-in', str(data), '-out', str(signature)], check=True, capture_output=True)
            altered['semantic']['signature'] = base64.b64encode(signature.read_bytes()).decode()
            with self.assertRaises(ValueError):
                self.call(envelope=altered)

    def test_wrong_key_collision_and_expiry(self):
        for identities in ({'author': 2, 'host': 2, 'semantic': 3, 'bot': 4},
                           {'author': 1, 'host': 2, 'semantic': 3, 'bot': 3},
                           {'author': 1, 'host': 2, 'semantic': True, 'bot': 4}):
            with self.assertRaises(ValueError):
                self.call(identities=identities)
        policy = copy.deepcopy(self.policy)
        policy['semantic']['public_key_pem'] = policy['host']['public_key_pem']
        policy['semantic']['key_sha256'] = policy['host']['key_sha256']
        with self.assertRaises(ValueError):
            self.call(policy=policy)
        with self.assertRaises(ValueError):
            self.call(now=datetime(2026, 11, 8, 13, tzinfo=timezone.utc))


if __name__ == '__main__':
    unittest.main()
