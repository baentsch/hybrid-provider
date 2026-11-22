# Copyright 2026 hybrid-provider contributors
# SPDX-License-Identifier: Apache-2.0
#
# pqc_corpus_common.py -- pure helpers shared by the unified corpus interop tool
# (test/pqc_corpus_interop.py) and scripts/check-pqc-certs-drift.sh.  Imported,
# not executed.  Uses OPENSSL_BIN (default: openssl) only through its callers.
#
# The tool itself is capability-driven and uses no OID arc: it walks the whole
# IETF-Hackathon/pqc-certificates corpus and asks, per artifact, "can anything
# loaded handle this?".  The one arc that survives here is the LAMPS composite
# arc -- not to filter the corpus, but because it is *our* scope: the drift
# script single-sources it (OID-table diff) and the tool treats it as must-pass
# so a brand-new composite OID the corpus ships is surfaced even before we serve
# it.

"""Pure helpers for the PQC corpus interop tool + drift script."""

import filecmp
import glob
import os
import re
import subprocess

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# The LAMPS composite OID arc (sigs .37..54, KEMs .55..66) -- this provider's
# scope.  scripts/check-pqc-certs-drift.sh imports this as the single source for
# its OID-table diff; the tool treats artifacts on it as must-pass (see module
# docstring).  NOT used to decide which corpus artifacts to read.
ARC = r'1\.3\.6\.1\.5\.5\.7\.6\.[0-9]+'

# Size of the standardized LAMPS composite arc: 18 signature OIDs (.37..54) and
# 12 KEM OIDs (.55..66).  Denominators of the composite coverage lines; frozen
# by draft-ietf-lamps-pq-composite-sigs / -composite-kem.  A composite OID in
# the corpus beyond these means the drafts grew and COMPOSITE_*_LIST wants a
# revisit.
N_COMPOSITE_SIG_OIDS = 18
N_COMPOSITE_KEM_OIDS = 12

RAW_BASE = ('https://raw.githubusercontent.com/'
            'IETF-Hackathon/pqc-certificates/master/providers')

# ---------------------------------------------------------------------------
# OID helpers
# ---------------------------------------------------------------------------

_ASN1_OBJECT_RE = re.compile(
    r'^\s*(\d+):d=\d+\s+hl=\s*(\d+)\s+l=\s*(\d+)\s+prim:\s+OBJECT')

# One OID token = a dotted run of >=4 arcs.  An artifact filename carrying two
# (catalyst_<a>_with_<b>, chameleon_...) is a dual-algorithm artifact, not the
# single algorithm a capability check probes.
_OID_TOKEN = re.compile(r'[0-9]+(?:\.[0-9]+){3,}')


def decode_oid_bytes(data):
    """Decode a DER OID value (content bytes, no tag/len) to dotted form.

    Pure-Python X.690 8.19 decoder: needed because ``openssl asn1parse`` prints
    an OID *by name* when libcrypto knows one (3.5+ names ML-DSA-44 etc.), so a
    textual grep misses those OIDs.  Decoding each OBJECT from its own bytes is
    independent of any name table.
    """
    if not data:
        return ''
    first = data[0]
    a = 0 if first < 40 else 1 if first < 80 else 2
    arcs = [a, first - 40 * a]
    val = 0
    for b in data[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            arcs.append(val)
            val = 0
    return '.'.join(str(x) for x in arcs)


def _objects(path, openssl_bin):
    """Yield (offset, hl, length) for every OBJECT asn1parse finds in a DER file.

    Null cnf: no providers, so asn1parse is a pure structural walk.
    """
    try:
        out = subprocess.run(
            [openssl_bin, 'asn1parse', '-inform', 'DER', '-in', path],
            capture_output=True, text=True,
            env={**os.environ, 'OPENSSL_CONF': os.devnull}).stdout
        with open(path, 'rb') as f:
            data = f.read()
    except (OSError, subprocess.SubprocessError):
        return
    for line in out.splitlines():
        m = _ASN1_OBJECT_RE.match(line)
        if m:
            off, hl, length = int(m.group(1)), int(m.group(2)), int(m.group(3))
            yield decode_oid_bytes(data[off + hl:off + hl + length])


def embedded_oids(path, arc=ARC, openssl_bin='openssl'):
    """Sorted, unique OIDs of family *arc* a DER file embeds (byte-decoded)."""
    arc_re = re.compile(arc + r'$')
    return sorted({o for o in _objects(path, openssl_bin) if arc_re.fullmatch(o)})


def oid_check(path, expected_oid, arc=ARC, openssl_bin='openssl'):
    """Check that *path* embeds exactly the single family OID *expected_oid*.

    Returns ``None`` if coherent, or an error-message string if not.  Applied
    only to must-pass (composite / ours) artifacts: a mislabeled artifact we are
    supposed to read is drift worth a FAIL; for algorithms we only qualify, the
    label is the peer's business.
    """
    emb = embedded_oids(path, arc, openssl_bin)
    if emb == [expected_oid]:
        return None
    base = os.path.basename(path)
    if not emb:
        return (f'{base}: no OID of the family inside (unparseable DER?), '
                f'expected its filename OID {expected_oid}')
    return (f'{base} embeds [{" ".join(emb)}] instead of its filename '
            f'OID {expected_oid}')


def file_oid(path):
    """The single OID in an artifact's filename, or '' if not exactly one.

    Arc-free: the corpus names every artifact for its algorithm OID, so the
    filename is the reliable key.  Dual-OID names are skipped (see _OID_TOKEN).
    """
    toks = _OID_TOKEN.findall(os.path.basename(path))
    return toks[0] if len(toks) == 1 else ''


def privs(base):
    """Every private key shipped for an artifact base, one path per entry.

    ``<base>_priv.der`` plus the per-form variants (``_seed_priv.der``,
    ``_expandedkey_priv.der``, ``_both_priv.der`` for ML-DSA / ML-KEM).
    """
    out = [p for p in [base + '_priv.der'] if os.path.isfile(p)]
    out += sorted(f for f in glob.glob(base + '_*_priv.der')
                  if os.path.isfile(f))
    return out


def report_oid(family, peer, oid):
    """Append a ``<family> <peer> <oid>`` line to ``$PQC_OID_REPORT``, if set."""
    path = os.environ.get('PQC_OID_REPORT', '')
    if path:
        with open(path, 'a') as f:
            f.write(f'{family} {peer} {oid}\n')


def files_equal(a, b):
    """True if files *a* and *b* have byte-identical contents."""
    try:
        return filecmp.cmp(a, b, shallow=False)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Platform helpers
# ---------------------------------------------------------------------------

def soext():
    """Return the shared-library extension for the current platform."""
    uname = os.uname().sysname if hasattr(os, 'uname') else 'Linux'
    if uname == 'Darwin':
        return os.environ.get('SOEXT', 'dylib')
    if uname.startswith(('MINGW', 'MSYS', 'CYGWIN')):
        return os.environ.get('SOEXT', 'dll')
    return os.environ.get('SOEXT', 'so')
