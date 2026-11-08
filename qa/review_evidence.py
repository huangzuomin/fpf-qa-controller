"""Offline signature/binding preflight; never grants authority to submit reviews.

All inputs including policy must be obtained by a future trusted caller. This
module cannot establish that origin and deliberately exposes no approval API.
"""
import base64
import hashlib
import json
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

SHA = re.compile(r'^[0-9a-f]{40}$')
DIGEST = re.compile(r'^[0-9a-f]{64}$')
ROLES = {'host', 'semantic'}
BINDINGS = {'controller_repo', 'controller_sha', 'candidate_repo', 'pr', 'head', 'base', 'task'}


def require(ok):
    if not ok:
        raise ValueError('evidence rejected')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def time_value(value):
    require(isinstance(value, str) and bool(re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value)))
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def verify(policy, envelope, evidence, expected, identities, now, openssl='openssl'):
    """Verify two externally signed statements against an independently trusted policy.

    On success returns only VERIFIED_INPUTS, not a review verdict. Never print
    exceptions or input values: the caller handles sensitive data locally.
    """
    try:
        require(set(expected) == BINDINGS and set(identities) == {'author', 'host', 'semantic', 'bot'})
        require(all(type(x) is int and x > 0 for x in identities.values()))
        require(len(set(identities.values())) == 4)
        require(expected['controller_repo'] == 'huangzuomin/fpf-qa-controller')
        require(expected['candidate_repo'] == 'huangzuomin/geo-service-core')
        require(type(expected['pr']) is int and expected['pr'] > 0)
        require(all(isinstance(expected[x], str) and SHA.fullmatch(expected[x]) for x in ('controller_sha', 'head', 'base')))
        require(isinstance(expected['task'], str) and bool(re.fullmatch(r'[A-Za-z0-9_-]{1,80}', expected['task'])))
        require(set(policy) == ROLES and set(envelope) == ROLES and set(evidence) == ROLES)
        require(now.tzinfo is not None and now.utcoffset().total_seconds() == 0)
        fingerprints = set()
        for role in sorted(ROLES):
            rule, item = policy[role], envelope[role]
            require(set(rule) == {'identity', 'public_key_pem', 'key_sha256'})
            require(type(rule['identity']) is int and rule['identity'] == identities[role])
            require(isinstance(rule['public_key_pem'], str) and len(rule['public_key_pem']) < 4096)
            require(isinstance(rule['key_sha256'], str) and bool(DIGEST.fullmatch(rule['key_sha256'])))
            require(set(item) == {'statement', 'signature'})
            statement = item['statement']
            require(set(statement) == {'version', 'role', 'identity', 'binding', 'issued_at', 'expires_at', 'result', 'evidence_sha256'})
            require(type(statement['version']) is int and statement['version'] == 1 and statement['role'] == role)
            require(type(statement['identity']) is int and statement['identity'] == identities[role])
            require(canonical(statement['binding']) == canonical(expected) and statement['result'] == 'PASS')
            digest = statement['evidence_sha256']
            require(isinstance(digest, str) and bool(DIGEST.fullmatch(digest)) and digest != '0' * 64)
            require(type(evidence[role]) is bytes and 0 < len(evidence[role]) <= 1048576)
            require(hashlib.sha256(evidence[role]).hexdigest() == digest)
            issued, expiry = time_value(statement['issued_at']), time_value(statement['expires_at'])
            require(issued <= now < expiry and 0 < (expiry - issued).total_seconds() <= 86400)
            signature = base64.b64decode(item['signature'], validate=True)
            require(len(signature) == 64)
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                key, data, sig = root / 'key.pem', root / 'data', root / 'signature'
                key.write_text(rule['public_key_pem'], encoding='ascii')
                data.write_bytes(canonical(statement))
                sig.write_bytes(signature)
                # DER digest pins actual key material, not a caller-supplied label.
                der = subprocess.run([openssl, 'pkey', '-pubin', '-in', str(key), '-outform', 'DER'],
                                     check=True, capture_output=True, timeout=10).stdout
                # Exact Ed25519 SubjectPublicKeyInfo prefix and 32-byte key.
                require(len(der) == 44 and der[:12] == bytes.fromhex('302a300506032b6570032100'))
                fingerprint = hashlib.sha256(der).hexdigest()
                require(fingerprint == rule['key_sha256'] and fingerprint not in fingerprints)
                fingerprints.add(fingerprint)
                subprocess.run([openssl, 'pkeyutl', '-verify', '-pubin', '-inkey', str(key), '-rawin',
                                '-in', str(data), '-sigfile', str(sig)], check=True, capture_output=True, timeout=10)
        return 'VERIFIED_INPUTS'
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, OSError, UnicodeError,
            subprocess.SubprocessError):
        raise ValueError('evidence rejected') from None
