#!/usr/bin/env python3
#
# pqc_kem_cms_certificates_interop.py -- composite ML-KEM CMS (KEMRI) interop
# against the IETF Hackathon PQC certificate artifact repository
# (github.com/IETF-Hackathon/pqc-certificates).  This is the CMS companion to:
#   - pqc_kem_certificates_interop.py  (raw composite-KEM DECAPS vectors), and
#   - pqc_kem_cms_interop.sh           (BOTH-WAY CMS interop vs carl-wallace's
#                                       kemri_toy, a single live peer).
#
# Here the peer is the corpus itself: each provider ships, per composite-KEM
# OID, a CMS EnvelopedData whose single recipient is a KEMRecipientInfo
# (RFC 9629), plus the recipient's PKCS#8 private key and the expected
# plaintext.  We decrypt their EnvelopedData with hybrid-provider and confirm
# we recover that plaintext -- "third party generated, we read", across a real
# implementation boundary and the full standardized combo matrix (the .55..66
# arc, incl. brainpool .61/.64, which kemri_toy cannot generate).
#
# Modes (mirroring pqc_kem_certificates_interop.py): `verify` (default) reads
# the peers' corpus; `generate` writes THIS provider's composite-KEM KEMRI
# EnvelopedData in the same cms_v3 layout (+ self-verify) for a
# providers/hybrid-provider/ submission so others can decrypt us; `all` does
# both.
#
# Floors / behaviour (opt-in harness; NOT wired into ctest -- needs network +
# the external corpus + a KEMRI-capable OpenSSL):
#   - OpenSSL 3.6.0+ : CMS KEM-recipient auto-selection landed in 3.6.0 with
#     KEMRI (commit d0899abb, PR 27681); 3.5 defaults a KEM key to key
#     transport.  Below 3.6 we self-skip.
#   - Composite components (ML-KEM + RSA/ECDH/X25519/X448) come from the
#     default provider (3.5+); the composite OIDs come from hybrid-provider.
# --strict (or STRICT=1) turns the "nothing to compare" outcomes from SKIP
# into FAIL.

import filecmp
import glob
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from pqc_corpus_common import ARC, PqcCorpus, oid_check, report_oid, skip_all

# Two independent draft-18 impls that ship the full .55..66 KEMRI matrix.
CMS_PEERS = 'composite-crypto bc'

# Our generated EnvelopedData payload.
PLAINTEXT = os.environ.get('PLAINTEXT', 'Hello, World!')


def _files_equal(a, b):
    try:
        return filecmp.cmp(a, b, shallow=False)
    except OSError:
        return False


def _version_gate(corpus):
    """Self-skip if OpenSSL < 3.6.0 (CMS KEMRI not available)."""
    try:
        r = subprocess.run([corpus.openssl_bin, 'version'],
                           capture_output=True, text=True)
        ver = r.stdout.strip()
    except OSError:
        skip_all(f'openssl ({corpus.openssl_bin}) not runnable')
        return  # unreachable
    m = re.match(r'OpenSSL (\d+)\.(\d+)\.', ver)
    if not m:
        skip_all(f'need OpenSSL 3.6.0+ for CMS KEMRI (have: {ver})')
    major, minor = int(m.group(1)), int(m.group(2))
    if major < 3 or (major == 3 and minor < 6):
        skip_all(f'need OpenSSL 3.6.0+ for CMS KEMRI (have: {ver})')


def verify_peer(corpus, peer):
    """Download and verify a single peer's composite-KEM CMS KEMRI blobs."""
    if not corpus.fetch_peer(peer):
        corpus.miss(f'{peer}: no artifacts_cms_{corpus.round}.zip '
                    f'(unreachable / absent)')
        return
    d = os.path.join(corpus.workdir, peer)
    arc_re = re.compile(ARC)

    # Find expected_plaintext.txt
    exp_files = glob.glob(os.path.join(d, '**', 'expected_plaintext.txt'),
                          recursive=True)
    if not exp_files:
        corpus.miss(f'{peer}: no expected_plaintext.txt in '
                    f'cms_{corpus.round} (cannot assert content)')
        return
    exp = exp_files[0]

    peer_oids_file = os.path.join(corpus.workdir, f'{peer}.oids')
    open(peer_oids_file, 'w').close()

    # One EnvelopedData per composite-KEM OID (HKDF-SHA256 KEMRI; exclude the
    # authenticated and user-keying-material variants).
    blob_files = sorted(
        f for f in glob.glob(
            os.path.join(d, '**', '*_kemri_id-alg-hkdf-with-sha256.der'),
            recursive=True)
        if arc_re.search(f) and '_kemri_auth' not in f)

    n = 0
    p = 0
    for blob in blob_files:
        base = re.sub(r'_kemri_id-alg-hkdf-with-sha256\.der$', '', blob)
        m = arc_re.search(base)
        if not m:
            continue
        oid = m.group()
        n += 1
        report_oid('cms', peer, oid)

        priv = f'{base}_priv.der'
        if not os.path.isfile(priv):
            corpus.no(f'{peer}: {oid} missing _priv.der')
            continue
        # The KEMRI's AlgorithmIdentifier and recipient key must both carry
        # the filename OID.
        why = oid_check(blob, oid, openssl_bin=corpus.openssl_bin)
        if not why:
            why = oid_check(priv, oid, openssl_bin=corpus.openssl_bin)
        if why:
            corpus.no(f'{peer}: {why}')
            continue

        out = os.path.join(corpus.workdir,
                           os.path.basename(base) + '.out')
        ok = corpus.oss_ok('cms', '-decrypt', '-inform', 'DER',
                           '-in', blob, '-inkey', priv, '-keyform', 'DER',
                           '-out', out)
        if ok and _files_equal(out, exp):
            p += 1
            with open(peer_oids_file, 'a') as f:
                f.write(oid + '\n')
            with open(os.path.join(corpus.workdir, 'verified_oids'), 'a') as f:
                f.write(oid + '\n')
        else:
            corpus.no(f'{peer}: {oid} ({os.path.basename(base)}) '
                      f'did not decrypt to expected plaintext')

    if n == 0:
        corpus.miss(f'{peer}: no composite-KEM ({ARC}) KEMRI artifacts '
                    f'in cms_{corpus.round}')
    else:
        with open(peer_oids_file) as f:
            dist = len(set(f.read().split()))
        msg = (f'{peer}: {dist}/12 composite-KEM OIDs decrypted to the '
               f'peer\'s plaintext ({p}/{n} blobs)')
        # Each failed blob already raised its own FAIL; the peer-summary line
        # is a PASS only when every found blob decrypted (p==n).
        if p == n:
            corpus.ok(msg)
        else:
            corpus.no(msg)


def cmd_verify(corpus):
    corpus.verify_all(
        'Read/verify: pqc-certificates composite ML-KEM CMS (KEMRI) '
        'decrypted by hybrid-provider',
        verify_peer)


def cmd_generate(corpus):
    corpus.hdr('Generate: hybrid-provider composite ML-KEM CMS KEMRI '
               'artifacts (cms_v3 layout) + self-verify')
    os.makedirs(corpus.outdir, exist_ok=True)
    arc_re = re.compile(ARC)

    # Ed25519 CA to sign the EE certs (a KEM key cannot self-sign).
    ca_key = os.path.join(corpus.workdir, 'ca.key')
    ca_crt = os.path.join(corpus.workdir, 'ca.crt')
    if not corpus.ossp_ok('genpkey', '-algorithm', 'ED25519', '-out', ca_key) \
            or not corpus.ossp_ok('x509', '-new', '-key', ca_key,
                                  '-subj', '/CN=hybrid-cms-kem-ca',
                                  '-days', '3650', '-out', ca_crt):
        corpus.note('cannot create Ed25519 CA cert')
        return

    pt_path = os.path.join(corpus.outdir, 'expected_plaintext.txt')
    with open(pt_path, 'w') as f:
        f.write(PLAINTEXT)

    # List KEM algorithms from the hybrid provider (via ossp -- null cnf)
    r = corpus.ossp('list', '-kem-algorithms')
    algs = []
    for line in (r.stdout or '').splitlines():
        line = line.strip()
        if '@ hybrid' in line or '@hybrid' in line:
            algs.append(line.split()[0])

    n = 0
    p = 0
    for alg in algs:
        key = os.path.join(corpus.workdir, f'{alg}.key')
        pub = os.path.join(corpus.workdir, f'{alg}.pub')
        if not corpus.ossp_ok('genpkey', '-algorithm', alg, '-out', key):
            continue
        if not corpus.ossp_ok('pkey', '-in', key, '-pubout',
                              '-outform', 'DER', '-out', pub):
            continue
        # asn1parse with null cnf to get the OID
        try:
            r2 = subprocess.run(
                [corpus.openssl_bin, 'asn1parse', '-inform', 'DER', '-in', pub],
                capture_output=True, text=True,
                env={**os.environ, 'OPENSSL_CONF': os.devnull})
            oids = sorted(set(re.findall(
                r'OBJECT\s*:\s*(' + ARC + r')$', r2.stdout, re.MULTILINE)))
        except OSError:
            continue
        if not oids:
            continue
        oid = oids[0]

        n += 1
        base = os.path.join(corpus.outdir, f'id-{alg}-{oid}')
        corpus.ossp_ok('pkey', '-in', key, '-outform', 'DER',
                       '-out', f'{base}_priv.der')
        # EE cert carrying the composite-KEM public key, signed by Ed25519 CA.
        ee_der = f'{base}_ee.der'
        kemri = f'{base}_kemri_id-alg-hkdf-with-sha256.der'
        if not corpus.ossp_ok('x509', '-new', '-force_pubkey', pub,
                              '-CA', ca_crt, '-CAkey', ca_key,
                              '-subj', f'/CN=ee-{oid}', '-days', '365',
                              '-out', ee_der, '-outform', 'DER') \
                or not corpus.ossp_ok('cms', '-encrypt', '-recip', ee_der,
                                      '-aes-256-cbc', '-binary',
                                      '-in', pt_path, '-outform', 'DER',
                                      '-out', kemri):
            corpus.no(f'{alg} ({oid}) could not produce EE cert / '
                      f'EnvelopedData')
            continue
        # Self-verify: decrypting our own EnvelopedData must recover plaintext.
        r3 = corpus.ossp('cms', '-decrypt', '-inform', 'DER',
                         '-in', kemri,
                         '-inkey', f'{base}_priv.der', '-keyform', 'DER')
        if r3.returncode == 0 and r3.stdout == PLAINTEXT:
            p += 1
        else:
            corpus.no(f'{alg} ({oid}) self-decrypt of generated '
                      f'EnvelopedData')

    if n == 0:
        corpus.note('no composite-KEM algorithms available '
                    '(needs OpenSSL 3.5+ ML-KEM + composite build)')
    else:
        corpus.ok(f'generated + self-verified {p}/{n} composite-KEM CMS '
                  f'artifacts -> {corpus.outdir}')
        print(f'       (submit these under providers/hybrid-provider/ as')
        print(f'        artifacts_cms_{corpus.round}.zip so peers can '
              f'decrypt our EnvelopedData)')


if __name__ == '__main__':
    corpus = PqcCorpus(
        kind='cms', outname='pqc-kem-cms-artifacts',
        default_peers=CMS_PEERS,
        zip_prefix='cms',
        round_flag='--version', round_default='v3', round_env='VER',
        version_gate_fn=_version_gate)
    corpus.main(cmd_verify, cmd_generate)
