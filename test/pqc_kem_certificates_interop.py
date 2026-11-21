#!/usr/bin/env python3
#
# pqc_kem_certificates_interop.py -- composite ML-KEM interop against the IETF
# Hackathon PQC certificate artifact repository
# (github.com/IETF-Hackathon/pqc-certificates), the KEM companion to
# pqc_certificates_interop.py (issue #31, which covers composite ML-DSA sigs).
#
# Our overlap is the LAMPS composite ML-KEM (draft-ietf-lamps-pq-composite-kem),
# whose r5 artifacts use the OID arc 1.3.6.1.5.5.7.6.55..66 -- exactly this
# provider's COMPOSITE_KEM_LIST.  Unlike a signature, a KEM public key cannot
# self-sign a trust anchor, so the interop is a DECAPSULATION check rather than
# a certificate verify: the reference provider ships, per OID, its serialized
# private key + a ciphertext + the expected shared secret; we decapsulate their
# ciphertext with their key and confirm we recover their secret.
#
# Modes:
#   verify    (default) Download each peer's artifacts_certs_<round>.zip and,
#             for every composite-KEM OID that ships a decaps vector, load its
#             PKCS#8 private key with hybrid-provider, decapsulate its
#             ciphertext, and check the recovered shared secret equals its
#             published one -- i.e. "third party generated, we read".
#   generate  Produce THIS provider's composite ML-KEM artifacts (PKCS#8
#             _priv.der, SPKI _pub.der, plus a self-encapsulated
#             _ciphertext.bin + _ss.bin) in the repo's r5 flat naming, then
#             self-verify by decapsulating.
#   all       verify, then generate.
#
# Composite components (ML-KEM + RSA/ECDH/X25519/X448) come from the default
# provider (OpenSSL 3.5+).  Everything self-skips (exit 0) when the peer zip
# cannot be fetched or a component is unavailable; a shared OID that fails to
# decapsulate to the reference secret is a real FAIL.
# --strict (or STRICT=1) turns the two "nothing to compare" outcomes from SKIP
# into FAIL.
# --family nist-pq with --providers runs the same checks on plain ML-DSA /
# SLH-DSA / ML-KEM from any component provider, hybrid not involved (see
# test/pqc_corpus_common.py).  An artifact the loaded providers cannot load is a
# SKIP (FAIL under --strict), not a wrong result.

import glob
import os
import re
import shutil
import sys

sys.path.insert(0, os.path.dirname(__file__))
from pqc_corpus_common import (PqcCorpus, embedded_oids, files_equal, name_oid,
                               oid_check, privs)

# composite-kem-ref-impl (LAMPS reference) first, then third-party providers
# that publish composite-KEM decaps vectors in the r5 round.
KEM_PEERS = 'composite-kem-ref-impl bc cht crypto4a cryptonext entrust'


def verify_peer(corpus, peer):
    """Verify one peer's family KEM decaps vectors across all key forms."""
    if not corpus.fetch_peer(peer):
        corpus.miss(f'{peer}: no artifacts_certs_{corpus.round}.zip '
                    f'(unreachable / absent)')
        return
    d = os.path.join(corpus.workdir, peer)
    arc_re = re.compile(corpus.arc)

    # One shared-secret file per KEM OID of the family; each shipped private-key
    # form (one _priv.der, or ML-KEM's _seed / _expandedkey / _both) is its own
    # vector against the same ciphertext.
    ss_files = sorted(f for f in glob.glob(os.path.join(d, '**', '*_ss.bin'),
                                           recursive=True)
                      if arc_re.search(f))
    n = p = u = 0
    for ss in ss_files:
        base = ss[:-len('_ss.bin')]
        oid = name_oid(base, corpus.arc)
        if not oid:
            continue
        corpus.report_oid('kem', peer, oid)

        ct = f'{base}_ciphertext.bin'
        key_forms = privs(base)
        if not key_forms or not os.path.isfile(ct):
            n += 1
            corpus.no(f'{peer}: {oid} missing _priv.der / _ciphertext.bin')
            continue
        for priv in key_forms:
            n += 1
            why = oid_check(priv, oid, corpus.arc, corpus.openssl_bin)
            if why:
                corpus.no(f'{peer}: {why}')
                continue
            if not corpus.key_loadable(priv):
                u += 1
                corpus.miss(f'{peer}: {oid} ({os.path.basename(priv)}) '
                            f'not loadable by: {corpus.providers}')
                continue
            out = os.path.join(corpus.workdir, os.path.basename(priv) + '.out')
            ok = corpus.oss_ok('pkeyutl', '-decap', '-inkey', priv,
                               '-keyform', 'DER', '-in', ct, '-secret', out)
            if ok and files_equal(out, ss):
                p += 1
                corpus.record_ok(peer, oid)
            else:
                corpus.no(f'{peer}: {oid} ({os.path.basename(priv)}) '
                          f'did not decapsulate to its secret')

    corpus.peer_summary(
        peer, n, p, "decapsulated to the peer's secret", 'vectors',
        f'no {corpus.family} ({corpus.arc}) KEM decaps vectors in '
        f'{corpus.round} (certs-only or none)', u)


def cmd_verify(corpus):
    corpus.verify_all(
        f'Read/verify: pqc-certificates {corpus.family} KEM decaps vectors',
        'decapsulated', verify_peer)


def cmd_generate(corpus):
    if not corpus.can_generate():
        return
    corpus.hdr('Generate: hybrid-provider composite ML-KEM artifacts '
               '(r5 layout) + self-verify')
    os.makedirs(corpus.outdir, exist_ok=True)

    # List KEM algorithms from the hybrid provider
    out = corpus.oss_output('list', '-kem-algorithms')
    algs = []
    for line in out.splitlines():
        line = line.strip()
        if '@ hybrid' in line or '@hybrid' in line:
            algs.append(line.split()[0])

    n = 0
    p = 0
    for alg in algs:
        key = os.path.join(corpus.workdir, f'{alg}.key')
        pub = os.path.join(corpus.workdir, f'{alg}.pub')
        if not corpus.oss_ok('genpkey', '-algorithm', alg, '-out', key):
            continue
        if not corpus.oss_ok('pkey', '-in', key, '-pubout',
                             '-outform', 'DER', '-out', pub):
            continue
        # Get OID from the public key
        oids = embedded_oids(pub, corpus.arc, corpus.openssl_bin)
        if not oids:
            continue
        oid = oids[0]

        n += 1
        base = os.path.join(corpus.outdir, f'id-{alg}-{oid}')
        corpus.oss_ok('pkey', '-in', key, '-outform', 'DER',
                      '-out', f'{base}_priv.der')
        shutil.copy2(pub, f'{base}_pub.der')
        corpus.oss_ok('pkeyutl', '-encap', '-inkey', pub, '-pubin',
                      '-keyform', 'DER',
                      '-out', f'{base}_ciphertext.bin',
                      '-secret', f'{base}_ss.bin')
        # Round-trip: decapsulating our own ciphertext must recover our secret.
        chk = os.path.join(corpus.workdir, f'{alg}.chk')
        ok = corpus.oss_ok('pkeyutl', '-decap',
                           '-inkey', f'{base}_priv.der', '-keyform', 'DER',
                           '-in', f'{base}_ciphertext.bin', '-secret', chk)
        if ok and files_equal(chk, f'{base}_ss.bin'):
            p += 1
        else:
            corpus.no(f'{alg} ({oid}) self-decapsulation of generated '
                      f'ciphertext')

    if n == 0:
        corpus.note('no composite-KEM algorithms available '
                    '(needs OpenSSL 3.5+ ML-KEM + composite build)')
    else:
        corpus.ok(f'generated + self-verified {p}/{n} composite ML-KEM '
                  f'artifacts -> {corpus.outdir}')
        print('       (submit these under providers/hybrid-provider/ so '
              'peers can')
        print('        decapsulate our ciphertexts and check our shared '
              'secrets)')


if __name__ == '__main__':
    corpus = PqcCorpus(kind='kem', outname='pqc-kem-artifacts',
                       default_peers=KEM_PEERS)
    corpus.main(cmd_verify, cmd_generate)
