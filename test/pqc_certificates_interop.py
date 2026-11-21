#!/usr/bin/env python3
#
# pqc_certificates_interop.py -- interop against the IETF Hackathon PQC
# certificate artifact repository (github.com/IETF-Hackathon/pqc-certificates).
#
# That repo is the canonical multi-vendor X.509 interop corpus: each provider
# uploads self-signed trust-anchor certs (+ keys) per algorithm/OID, and CI
# cross-verifies everyone against everyone.  Our overlap is the LAMPS composite
# ML-DSA signatures (draft-ietf-lamps-pq-composite-sigs), whose r5 artifacts
# use the OID arc 1.3.6.1.5.5.7.6.37..54 -- exactly this provider's
# COMPOSITE_SIG_LIST.
#
# Modes:
#   verify    (default) Download each peer's artifacts_certs_<round>.zip and
#             verify every composite trust-anchor cert (matched by OID) with
#             hybrid-provider -- i.e. "third party generated, we read".  Reports
#             a per-peer pass/fail matrix.
#   generate  Produce THIS provider's composite artifacts (self-signed _ta cert
#             in DER+PEM and a PKCS#8 _priv key) in the repo's r5 flat naming,
#             then self-verify them.  This is the set to zip as
#             artifacts_certs_r5.zip for a providers/hybrid-provider/ submission,
#             so the repo's CI (OQS docker + other providers) can verify US --
#             the reverse direction, run there rather than here.
#   all       verify, then generate.
#
# Composite components (ML-DSA + RSA/ECDSA/EdDSA) come from the default
# provider (OpenSSL 3.5+).  Everything self-skips (exit 0) when a peer zip
# cannot be fetched or a component is unavailable; a shared OID that fails to
# verify is a real FAIL.  Not wired into ctest (needs network + an external
# corpus).
# --strict (or STRICT=1) turns the two "nothing to compare" outcomes of a
# verify -- a peer zip that cannot be fetched, and a peer with no artifacts on
# our arc -- from SKIP into FAIL.  Scheduled drift checks
# (scripts/check-pqc-certs-drift.sh) use it: there a vanished or renamed peer
# is drift to triage, not a clean skip.

import glob
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from pqc_corpus_common import ARC, PqcCorpus, embedded_oids, oid_check, report_oid

# Default peers = every provider that publishes draft-19 composite-signature
# artifacts in the r5 round.
SIG_PEERS = ('bc carl-redhound cht composite-crypto composite-sigs-ref-impl '
             'crypto4a cryptonext entrust entrust-pkihub leancrypto '
             'openssl-composite-preliminary-impl safelogic')


def verify_peer(corpus, peer):
    """Download and verify a single peer's composite trust-anchor certs."""
    if not corpus.fetch_peer(peer):
        corpus.miss(f'{peer}: no artifacts_certs_{corpus.round}.zip '
                    f'(unreachable / absent)')
        return
    d = os.path.join(corpus.workdir, peer)
    peer_oids_file = os.path.join(corpus.workdir, f'{peer}.oids')
    open(peer_oids_file, 'w').close()
    arc_re = re.compile(ARC)

    # Composite trust-anchor certs, matched by the arc OID in the filename.
    ta_files = sorted(f for f in glob.glob(os.path.join(d, '**', '*_ta.der'),
                                           recursive=True)
                      if arc_re.search(f))
    n = 0
    p = 0
    for ta in ta_files:
        m = arc_re.search(ta)
        if not m:
            continue
        oid = m.group()
        n += 1
        pem = ta + '.pem'
        report_oid('sig', peer, oid)

        # The OID in the name must be the one inside: cert and key, if shipped.
        priv = re.sub(r'_ta\.der$', '_priv.der', ta)
        why = oid_check(ta, oid, openssl_bin=corpus.openssl_bin)
        if why:
            corpus.no(f'{peer}: {why}')
            continue
        if os.path.isfile(priv):
            why = oid_check(priv, oid, openssl_bin=corpus.openssl_bin)
            if why:
                corpus.no(f'{peer}: {why}')
                continue

        # Convert to PEM for verify
        if not corpus.oss_ok('x509', '-inform', 'DER', '-in', ta, '-out', pem):
            pem = ta
        if corpus.oss_ok('verify', '-no_check_time', '-CAfile', pem, pem):
            p += 1
            with open(os.path.join(corpus.workdir, 'verified_oids'), 'a') as f:
                f.write(oid + '\n')
            with open(peer_oids_file, 'a') as f:
                f.write(oid + '\n')
        else:
            corpus.no(f'{peer}: {oid} ({os.path.basename(ta)}) '
                      f'not verified by hybrid-provider')

    if n == 0:
        corpus.miss(f'{peer}: no composite ({ARC}) trust-anchor certs '
                    f'in {corpus.round}')
    else:
        with open(peer_oids_file) as f:
            dist = len(set(f.read().split()))
        corpus.ok(f'{peer}: {dist} distinct composite OIDs verified '
                  f'({p}/{n} certs incl. duplicates)')


def cmd_verify(corpus):
    corpus.verify_all(
        'Read/verify: pqc-certificates composite certs verified by hybrid-provider',
        verify_peer)


def cmd_generate(corpus):
    corpus.hdr('Generate: hybrid-provider composite artifacts '
               '(r5 layout) + self-verify')
    os.makedirs(corpus.outdir, exist_ok=True)
    arc_re = re.compile(ARC)

    # List signature algorithms from the hybrid provider
    out = corpus.oss_output('list', '-signature-algorithms')
    algs = []
    for line in out.splitlines():
        line = line.strip()
        if '@ hybrid' in line or '@hybrid' in line:
            algs.append(line.split()[0])

    n = 0
    p = 0
    for alg in algs:
        key = os.path.join(corpus.workdir, f'{alg}.key')
        crt = os.path.join(corpus.workdir, f'{alg}.crt')
        if not corpus.oss_ok('genpkey', '-algorithm', alg, '-out', key):
            continue
        if not corpus.oss_ok('req', '-x509', '-key', key,
                             '-subj', f'/CN=hybrid-provider {alg}',
                             '-days', '3650', '-out', crt):
            continue
        # Get OID from the generated cert
        r = corpus.oss('x509', '-in', crt, '-outform', 'DER',
                       check=False, capture=True)
        if r.returncode != 0:
            continue
        # Write DER to temp, parse it
        der_tmp = os.path.join(corpus.workdir, f'{alg}.crt.der')
        # Need binary output -- use a different approach
        try:
            subprocess.run(
                [corpus.openssl_bin, 'x509', '-in', crt, '-outform', 'DER',
                 '-out', der_tmp],
                env={**os.environ, 'OPENSSL_CONF': corpus.cnf},
                capture_output=True, check=True)
        except (subprocess.CalledProcessError, OSError):
            continue
        oids = embedded_oids(der_tmp, ARC, corpus.openssl_bin)
        if not oids:
            continue
        oid = oids[0]

        n += 1
        base = os.path.join(corpus.outdir, f'id-{alg}-{oid}')
        # DER cert
        try:
            subprocess.run(
                [corpus.openssl_bin, 'x509', '-in', crt, '-outform', 'DER',
                 '-out', f'{base}_ta.der'],
                env={**os.environ, 'OPENSSL_CONF': corpus.cnf},
                capture_output=True, check=True)
        except (subprocess.CalledProcessError, OSError):
            pass
        # PEM cert
        shutil.copy2(crt, f'{base}_ta.pem')
        # DER private key
        corpus.oss_ok('pkey', '-in', key, '-outform', 'DER',
                      '-out', f'{base}_priv.der')
        # Round-trip: our own trust anchor must verify under hybrid-provider.
        if corpus.oss_ok('verify', '-no_check_time',
                         '-CAfile', f'{base}_ta.pem', f'{base}_ta.pem'):
            p += 1
        else:
            corpus.no(f'{alg} ({oid}) self-verify of generated trust anchor')

    if n == 0:
        corpus.note('no composite algorithms available '
                    '(needs OpenSSL 3.5+ ML-DSA + composite build)')
    else:
        corpus.ok(f'generated + self-verified {p}/{n} composite '
                  f'artifacts -> {corpus.outdir}')
        print(f'       (zip these as artifacts_certs_{corpus.round}.zip for a')
        print(f'        providers/hybrid-provider/ submission to have '
              f'others verify us)')


if __name__ == '__main__':
    corpus = PqcCorpus(kind='certs', outname='pqc-artifacts',
                       default_peers=SIG_PEERS)
    corpus.main(cmd_verify, cmd_generate)
