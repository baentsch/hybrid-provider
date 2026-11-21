# Copyright 2026 hybrid-provider contributors
# SPDX-License-Identifier: Apache-2.0
#
# pqc_corpus_common.py -- shared by the IETF Hackathon pqc-certificates corpus
# scripts (test/pqc_*certificates_interop.py) and scripts/check-pqc-certs-drift.sh.
# Imported, not executed.  Uses OPENSSL_BIN (default: openssl).
#
# What is tested is selectable (option or env; the defaults test this provider):
#   PQC_FAMILY    composite (the LAMPS composite arc, served by hybrid) or
#                 nist-pq (plain ML-DSA / SLH-DSA / ML-KEM from a component
#                 provider: "pass-through", hybrid is not involved)
#   PQC_PROVIDERS providers to load, each "name" or "name=/path/module"
#                 (default: "default hybrid").  For nist-pq, drop hybrid to
#                 qualify a component provider alone; keep it to check co-loading
#                 hybrid breaks nothing.
#   PQC_PROPQ     optional default property query (e.g. "?provider=oqsprovider")
#                 to pin which loaded provider serves a contested algorithm.
#   PQC_RAW_BASE  corpus root override (a local mirror, or file:// for tests)

"""Shared helpers for PQC certificate corpus interop scripts."""

import argparse
import filecmp
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# OID families.  The selected one is the regex every artifact is keyed on.
#  composite: the whole LAMPS composite arc (sigs .37..54, KEMs .55..66).  The
#    KEM scripts match all of it, not just the OIDs we serve today: only KEMs
#    ship decaps vectors and KEMRI blobs, so the match stays KEM-only, and a NEW
#    composite OID in the corpus is tried instead of being silently ignored.
#  nist-pq: the NIST CSOR OIDs of FIPS 203/204/205 (frozen; curated by hand):
#    sigAlgs .3.17-19 ML-DSA, .3.20-31 SLH-DSA, .3.32-34 HashML-DSA,
#    .3.35-46 HashSLH-DSA; kems .4.1-3 ML-KEM.
ARC_COMPOSITE = r'1\.3\.6\.1\.5\.5\.7\.6\.[0-9]+'
ARC_NIST_PQ = r'2\.16\.840\.1\.101\.3\.4\.(3\.(1[7-9]|[23][0-9]|4[0-6])|4\.[1-3])'
# Module-level default = composite; scripts/check-pqc-certs-drift.sh imports this
# (it only ever checks the composite arc).
ARC = ARC_COMPOSITE

# Corpus root; PQC_RAW_BASE overrides it (a local mirror, or file:// for tests).
RAW_BASE = os.environ.get(
    'PQC_RAW_BASE',
    'https://raw.githubusercontent.com/'
    'IETF-Hackathon/pqc-certificates/master/providers')

# ---------------------------------------------------------------------------
# OID helpers
# ---------------------------------------------------------------------------

def decode_oid_bytes(data):
    """Decode a DER-encoded OID value (content bytes, no tag/len) to dotted form.

    Pure-Python X.690 8.19 decoder: needed because ``openssl asn1parse`` prints
    an OID *by name* when libcrypto knows one (3.5+ names ML-DSA-44 etc.), so a
    textual grep misses the NIST PQ OIDs.  Decoding each OBJECT from its own
    bytes is independent of any name table.
    """
    if not data:
        return ''
    # First octet encodes the first two arcs: 40*X + Y, X in {0,1,2}.
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


_ASN1_OBJECT_RE = re.compile(
    r'^\s*(\d+):d=\d+\s+hl=\s*(\d+)\s+l=\s*(\d+)\s+prim:\s+OBJECT')


def embedded_oids(path, arc=ARC, openssl_bin='openssl'):
    """Return the sorted, unique OIDs of family *arc* that a DER file embeds.

    Runs ``openssl asn1parse`` with a null cnf (no providers) to locate each
    OBJECT, then decodes it from its own content bytes at the reported offset
    (see :func:`decode_oid_bytes`), independent of any name table.
    """
    try:
        out = subprocess.run(
            [openssl_bin, 'asn1parse', '-inform', 'DER', '-in', path],
            capture_output=True, text=True,
            env={**os.environ, 'OPENSSL_CONF': os.devnull},
        ).stdout
        with open(path, 'rb') as f:
            data = f.read()
    except (OSError, subprocess.SubprocessError):
        return []
    arc_re = re.compile(arc + r'$')
    found = set()
    for line in out.splitlines():
        m = _ASN1_OBJECT_RE.match(line)
        if not m:
            continue
        off, hl, length = int(m.group(1)), int(m.group(2)), int(m.group(3))
        oid = decode_oid_bytes(data[off + hl:off + hl + length])
        if arc_re.fullmatch(oid):
            found.add(oid)
    return sorted(found)


def oid_check(path, expected_oid, arc=ARC, openssl_bin='openssl'):
    """Check that *path* embeds exactly the single family OID *expected_oid*.

    Returns ``None`` if coherent, or an error-message string if not.
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


def name_oid(path, arc=ARC):
    """The single family OID in an artifact's filename, or '' if not exactly one.

    Names carrying two OIDs (``catalyst_<a>_with_<b>``, ``chameleon_...``, an
    older composite form) are multi-algorithm artifacts, not the single
    algorithm a family checks, so they are left out.
    """
    b = os.path.basename(path)
    if len(re.findall(r'[0-9]+(?:\.[0-9]+){3,}', b)) != 1:
        return ''
    m = re.search(arc, b)
    return m.group() if m else ''


def privs(base):
    """Every private key shipped for an artifact base, one path per entry.

    ``<base>_priv.der`` plus the per-form variants (``_seed_priv.der``,
    ``_expandedkey_priv.der``, ``_both_priv.der`` for ML-DSA / ML-KEM).
    """
    out = [p for p in [base + '_priv.der'] if os.path.isfile(p)]
    out += sorted(f for f in glob.glob(base + '_*_priv.der')
                  if os.path.isfile(f))
    return out


def files_equal(a, b):
    """Return True if files *a* and *b* have byte-identical contents.

    Used by the KEM scripts to compare a recovered shared secret / decrypted
    plaintext against the peer's reference file.
    """
    try:
        return filecmp.cmp(a, b, shallow=False)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Platform helpers
# ---------------------------------------------------------------------------

def _soext():
    """Return the shared-library extension for the current platform."""
    uname = os.uname().sysname if hasattr(os, 'uname') else 'Linux'
    if uname == 'Darwin':
        return os.environ.get('SOEXT', 'dylib')
    if uname.startswith(('MINGW', 'MSYS', 'CYGWIN')):
        return os.environ.get('SOEXT', 'dll')
    return os.environ.get('SOEXT', 'so')


# ---------------------------------------------------------------------------
# PqcCorpus -- shared scaffolding for the corpus interop scripts
# ---------------------------------------------------------------------------

class PqcCorpus:
    """Shared state and helpers for the PQC corpus interop scripts."""

    def __init__(self, kind, outname, default_peers, zip_prefix='certs',
                 round_flag='--round', round_default='r5', round_env='ROUND',
                 extra_args_fn=None, version_gate_fn=None):
        self.kind = kind              # 'certs', 'kem', 'cms'
        self.outname = outname        # default output dirname under module_dir
        self.default_peers = default_peers
        self.zip_prefix = zip_prefix  # 'certs' or 'cms'
        self.round_flag = round_flag
        self.round_default = round_default
        self.round_env = round_env
        self.extra_args_fn = extra_args_fn      # optional callback(parser)
        self.version_gate_fn = version_gate_fn  # optional callback(corpus)

        # Filled by parse_args / setup
        self.openssl_bin = 'openssl'
        self.openssl_libpath = ''
        self.module_dir = ''
        self.peers = ''
        self.round = round_default
        self.outdir = ''
        self.keep = False
        self.strict = False
        self.mode = 'verify'
        self.family = 'composite'
        self.providers = 'default hybrid'
        self.propq = ''
        self.arc = ARC_COMPOSITE
        self.soext = _soext()

        # Runtime state
        self.workdir = ''
        self.cnf = ''
        self.pass_count = 0
        self.fail_count = 0
        self.skip_count = 0
        self._use_color = False

    # ---- CLI ---------------------------------------------------------------

    def build_parser(self, description=''):
        p = argparse.ArgumentParser(
            description=description,
            formatter_class=argparse.RawDescriptionHelpFormatter)
        repo = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        p.add_argument('--openssl', default=os.environ.get('OPENSSL_BIN', 'openssl'),
                        help='openssl binary (default: %(default)s)')
        p.add_argument('--libpath', default=os.environ.get('OPENSSL_LIBPATH', ''),
                        help='LD_LIBRARY_PATH for libs')
        p.add_argument('--module-dir',
                        default=os.environ.get('MODULE_DIR',
                                               os.path.join(repo, 'build')),
                        help='OPENSSL_MODULES with hybrid.SOEXT (default: %(default)s)')
        p.add_argument('--peers', default=os.environ.get('PEERS', self.default_peers),
                        help='provider dirs to verify (space-separated)')
        p.add_argument(self.round_flag,
                        default=os.environ.get(self.round_env, self.round_default),
                        dest='round',
                        help='artifact round (default: %(default)s)')
        p.add_argument('--family', default=os.environ.get('PQC_FAMILY', 'composite'),
                        choices=['composite', 'nist-pq'],
                        help='composite | nist-pq (default: %(default)s)')
        p.add_argument('--providers',
                        default=os.environ.get('PQC_PROVIDERS', 'default hybrid'),
                        help='providers to load: "name" or "name=/path/module" '
                             'each (default: %(default)s)')
        p.add_argument('--propquery', dest='propq',
                        default=os.environ.get('PQC_PROPQ', ''),
                        help='default property query, e.g. "?provider=oqsprovider"')
        p.add_argument('--outdir', default='',
                        help=f'generate output dir (default: <module-dir>/{self.outname})')
        p.add_argument('--keep', action='store_true',
                        help='keep the temp work dir')
        p.add_argument('--strict', action='store_true',
                        default=os.environ.get('STRICT', '0') == '1',
                        help='unreachable / empty peer / unserved algorithm is '
                             'FAIL, not SKIP')
        p.add_argument('mode', nargs='?', default='verify',
                        choices=['verify', 'generate', 'all'],
                        help='verify (default), generate, or all')
        if self.extra_args_fn:
            self.extra_args_fn(p)
        return p

    def parse_args(self, argv=None):
        p = self.build_parser()
        args = p.parse_args(argv)
        self.openssl_bin = args.openssl
        self.openssl_libpath = args.libpath
        self.module_dir = args.module_dir
        self.peers = args.peers
        self.round = args.round
        self.family = args.family
        self.providers = args.providers
        self.propq = args.propq
        self.outdir = args.outdir
        self.keep = args.keep
        self.strict = args.strict
        self.mode = args.mode
        self.arc = ARC_COMPOSITE if self.family == 'composite' else ARC_NIST_PQ
        return args

    # ---- providers ---------------------------------------------------------

    def has_provider(self, name):
        """Is NAME one of the providers to load?"""
        return any(e.split('=', 1)[0] == name for e in self.providers.split())

    def _write_cnf(self, hybrid_path):
        """Generate the provider cnf from the --providers list.

        A bare name is a built-in or resolved in OPENSSL_MODULES (hybrid:
        *hybrid_path*); name=/path names the module explicitly.
        """
        lines = ['openssl_conf = c', '[c]', 'providers = p']
        if self.propq:
            lines.append('alg_section = a')
        lines.append('[p]')
        for e in self.providers.split():
            lines.append(f'{e.split("=", 1)[0]} = s_{e.split("=", 1)[0]}')
        for e in self.providers.split():
            name = e.split('=', 1)[0]
            mod = e.split('=', 1)[1] if '=' in e else ''
            if name == 'hybrid' and not mod:
                mod = hybrid_path
            lines.append(f'[s_{name}]')
            if mod:
                lines.append(f'module = {mod}')
            lines.append('activate = 1')
        if self.propq:
            lines += ['[a]', f'default_properties = {self.propq}']
        with open(self.cnf, 'w') as f:
            f.write('\n'.join(lines) + '\n')

    # ---- setup -------------------------------------------------------------

    def setup(self):
        """Create workdir, write cnf, guard providers.  Call after parse_args."""
        if os.path.isdir(self.module_dir):
            self.module_dir = os.path.realpath(self.module_dir)
        if not self.outdir:
            self.outdir = os.path.join(self.module_dir, self.outname)

        if self.openssl_libpath:
            ld = os.environ.get('LD_LIBRARY_PATH', '')
            parts = [self.openssl_libpath] + ([ld] if ld else [])
            os.environ['LD_LIBRARY_PATH'] = ':'.join(parts)
        os.environ['OPENSSL_MODULES'] = self.module_dir

        # Version gate (CMS needs 3.6.0+)
        if self.version_gate_fn:
            self.version_gate_fn(self)

        self._use_color = sys.stdout.isatty()

        # The hybrid module must exist only when hybrid is to be loaded.
        hybrid_path = os.path.join(self.module_dir, f'hybrid.{self.soext}')
        if self.has_provider('hybrid') and not os.path.isfile(hybrid_path):
            print(f'hybrid.{self.soext} not found in {self.module_dir} '
                  f'-- build the provider first', file=sys.stderr)
            sys.exit(1)

        self.workdir = tempfile.mkdtemp()
        self.cnf = os.path.join(self.workdir, 'providers.cnf')
        self._write_cnf(hybrid_path)

        # Guard: OpenSSL silently drops a cnf-referenced provider that fails to
        # load (lazy, non-fatal activation: exit 0, nothing on stderr); then
        # `list -providers` just omits it, and every check would "fail" with no
        # hint why.  Fail loudly, with the one diagnostic OpenSSL won't give us.
        listed = self.oss('list', '-providers', check=False, capture=True).stdout or ''
        active = {ln.strip() for ln in listed.splitlines()
                  if ln.startswith('  ') and not ln.startswith('   ')}
        for e in self.providers.split():
            name = e.split('=', 1)[0]
            if name in active:
                continue
            ver = self._openssl_version()
            print(f"ERROR: provider '{name}' did not activate under "
                  f"{self.openssl_bin} ({ver}).", file=sys.stderr)
            print('       Likely a wrong module path, an ABI/libcrypto mismatch '
                  'or a missing component dependency.', file=sys.stderr)
            sys.exit(1)

    def can_generate(self):
        """generate writes hybrid's composite artifacts: needs composite+hybrid."""
        if self.family == 'composite' and self.has_provider('hybrid'):
            return True
        self.note("generate writes hybrid-provider's composite artifacts: "
                  "needs --family composite with hybrid in --providers")
        return False

    def cleanup(self):
        if not self.keep and self.workdir and os.path.isdir(self.workdir):
            shutil.rmtree(self.workdir, ignore_errors=True)

    # ---- output helpers ----------------------------------------------------

    def _c(self, code, text):
        if self._use_color:
            return f'\033[{code}m{text}\033[0m'
        return text

    def ok(self, msg):
        print(f'  {self._c(32, "PASS")}  {msg}')
        self.pass_count += 1

    def no(self, msg):
        print(f'  {self._c(31, "FAIL")}  {msg}')
        self.fail_count += 1

    def note(self, msg):
        print(f'  {self._c(33, "SKIP")}  {msg}')
        self.skip_count += 1

    def miss(self, msg):
        """Nothing comparable (peer, or an algorithm no loaded provider serves):
        SKIP by default, FAIL under --strict."""
        if self.strict:
            self.no(msg)
        else:
            self.note(msg)

    def hdr(self, msg):
        print()
        print(f'== {msg} ==')

    # ---- subprocess --------------------------------------------------------

    def oss(self, *args, check=True, capture=False):
        """Run openssl with the provider cnf."""
        env = {**os.environ, 'OPENSSL_CONF': self.cnf}
        kw = dict(env=env)
        if capture:
            kw['capture_output'] = True
            kw['text'] = True
        else:
            kw['stdout'] = subprocess.DEVNULL
            kw['stderr'] = subprocess.DEVNULL
        if check:
            kw['check'] = True
        try:
            return subprocess.run([self.openssl_bin] + list(args), **kw)
        except (subprocess.CalledProcessError, OSError):
            if check:
                raise
            return subprocess.CompletedProcess(args, 1, stdout='', stderr='')

    def oss_ok(self, *args):
        """Run openssl; return True on success, False on failure."""
        try:
            self.oss(*args, check=True)
            return True
        except (subprocess.CalledProcessError, OSError):
            return False

    def oss_output(self, *args):
        """Run openssl; return stdout as string (empty on failure)."""
        r = self.oss(*args, check=False, capture=True)
        return r.stdout if r.returncode == 0 else ''

    def ossp(self, subcmd, *args):
        """Run openssl with null cnf + explicit -provider flags.

        Needed when the cnf's [default] section interferes (e.g. ``x509 -new``
        misreads it as cert extensions).  Only used by composite generate, which
        is always default + hybrid.
        """
        env = {**os.environ, 'OPENSSL_CONF': os.devnull}
        try:
            return subprocess.run(
                [self.openssl_bin, subcmd,
                 '-provider', 'default', '-provider', 'hybrid'] + list(args),
                env=env, capture_output=True, text=True, check=True,
            )
        except (subprocess.CalledProcessError, OSError):
            return subprocess.CompletedProcess(args, 1, stdout='', stderr='')

    def ossp_ok(self, subcmd, *args):
        """Run ossp; return True on success."""
        r = self.ossp(subcmd, *args)
        return r.returncode == 0

    def _openssl_version(self):
        try:
            r = subprocess.run([self.openssl_bin, 'version'],
                               capture_output=True, text=True)
            return r.stdout.strip()
        except OSError:
            return 'unknown'

    # ---- loadability -------------------------------------------------------

    def cert_loadable(self, path):
        """Can the loaded providers decode this cert at all?"""
        return self.oss_ok('x509', '-in', path, '-noout', '-pubkey')

    def key_loadable(self, path):
        """Can the loaded providers decode this DER private key at all?"""
        return self.oss_ok('pkey', '-in', path, '-inform', 'DER', '-noout')

    # ---- OID bookkeeping ---------------------------------------------------

    def report_oid(self, family, peer, oid):
        """Record a shipped OID: into shipped_oids, and $PQC_OID_REPORT if set."""
        if self.workdir:
            with open(os.path.join(self.workdir, 'shipped_oids'), 'a') as f:
                f.write(oid + '\n')
        path = os.environ.get('PQC_OID_REPORT', '')
        if path:
            with open(path, 'a') as f:
                f.write(f'{family} {peer} {oid}\n')

    def record_ok(self, peer, oid):
        """Record an OID that a peer verified under the loaded providers."""
        with open(os.path.join(self.workdir, f'{peer}.oids'), 'a') as f:
            f.write(oid + '\n')
        with open(os.path.join(self.workdir, 'verified_oids'), 'a') as f:
            f.write(oid + '\n')

    def peer_summary(self, peer, n, p, passing, unit, miss_text, u=0):
        """Per-peer verdict: n artifacts tried, p passed, u not loadable.

        Each failed artifact already raised its own FAIL; the summary is a PASS
        only when every loadable one passed, so a total failure never shows as a
        green "0/N ... PASS".
        """
        if n == 0:
            self.miss(f'{peer}: {miss_text}')
            return
        if u == n:          # nothing loadable: the per-artifact misses say it
            return
        uns = f', {u} not loadable' if u > 0 else ''
        with open(os.path.join(self.workdir, f'{peer}.oids')) as f:
            dist = len(set(f.read().split()))
        msg = f'{peer}: {dist} distinct OIDs {passing} ({p}/{n - u} {unit}{uns})'
        if p == n - u:
            self.ok(msg)
        else:
            self.no(msg)

    # ---- peer fetch --------------------------------------------------------

    def fetch_peer(self, peer):
        """Download and unzip a peer's artifact zip.  Returns True if OK."""
        zipfile = os.path.join(self.workdir, f'{peer}.zip')
        d = os.path.join(self.workdir, peer)
        url = f'{RAW_BASE}/{peer}/artifacts_{self.zip_prefix}_{self.round}.zip'
        try:
            r = subprocess.run(
                ['curl', '-fsSL', url, '-o', zipfile],
                capture_output=True, timeout=60)
            if r.returncode != 0 or not os.path.isfile(zipfile) \
                    or os.path.getsize(zipfile) == 0:
                return False
        except (OSError, subprocess.TimeoutExpired):
            return False
        os.makedirs(d, exist_ok=True)
        subprocess.run(['unzip', '-qo', zipfile, '-d', d],
                       capture_output=True)
        open(os.path.join(self.workdir, f'{peer}.oids'), 'w').close()
        return True

    # ---- verify loop -------------------------------------------------------

    def verify_all(self, header, passing, verify_peer_fn):
        """Run *verify_peer_fn* for each peer; print header + summary.

        *passing* is the past-tense verb for the "distinct OIDs ... from >=1
        peer" total (e.g. "verified", "decapsulated", "decrypted").
        """
        self.hdr(header)
        ver = self._openssl_version()
        print(f'  corpus: artifacts_{self.zip_prefix}_{self.round}.zip   '
              f'openssl: {ver}')
        print(f'  family: {self.family}   providers: {self.providers}'
              + (f'   propquery: {self.propq}' if self.propq else ''))
        open(os.path.join(self.workdir, 'verified_oids'), 'w').close()
        open(os.path.join(self.workdir, 'shipped_oids'), 'w').close()
        for peer in self.peers.split():
            verify_peer_fn(self, peer)
        shipped = os.path.join(self.workdir, 'shipped_oids')
        if os.path.getsize(shipped) > 0:
            with open(os.path.join(self.workdir, 'verified_oids')) as f:
                nv = len(set(f.read().split()))
            with open(shipped) as f:
                ns = len(set(f.read().split()))
            print(f'  distinct OIDs {passing} from >=1 peer: {nv} '
                  f'(of {ns} shipped)')

    # ---- main dispatch -----------------------------------------------------

    def main(self, cmd_verify, cmd_generate, argv=None):
        """Parse args, setup, dispatch, print summary, exit."""
        self.parse_args(argv)
        self.setup()
        try:
            if self.mode in ('verify', 'all'):
                cmd_verify(self)
            if self.mode in ('generate', 'all'):
                cmd_generate(self)
            self.hdr(f'Summary ({self.mode})')
            print(f'  passed: {self.pass_count}   failed: {self.fail_count}'
                  f'   skipped: {self.skip_count}')
            sys.exit(0 if self.fail_count == 0 else 1)
        finally:
            self.cleanup()


# ---------------------------------------------------------------------------
# Skip-all helper (for the CMS script's version gate)
# ---------------------------------------------------------------------------

def skip_all(msg):
    """Print SKIP and exit 0 — for environment gaps, not failures."""
    print(f'SKIP: {msg}')
    sys.exit(0)
