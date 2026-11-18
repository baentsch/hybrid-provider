# Copyright 2026 hybrid-provider contributors
# SPDX-License-Identifier: Apache-2.0
#
# pqc_corpus_common.py -- shared by the IETF Hackathon pqc-certificates corpus
# scripts (test/pqc_*certificates_interop.py) and scripts/check-pqc-certs-drift.sh.
# Imported, not executed.  Uses OPENSSL_BIN (default: openssl).

"""Shared helpers for PQC certificate corpus interop scripts."""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# The whole LAMPS composite OID arc (sigs .37..54, KEMs .55..66).  The KEM
# scripts match all of it, not just the OIDs we serve today: only KEMs ship
# decaps vectors and KEMRI blobs, so the match stays KEM-only, and a NEW
# composite OID in the corpus is tried (and FAILs) instead of being silently
# ignored.
ARC = r'1\.3\.6\.1\.5\.5\.7\.6\.[0-9]+'

RAW_BASE = ('https://raw.githubusercontent.com/'
            'IETF-Hackathon/pqc-certificates/master/providers')

# ---------------------------------------------------------------------------
# OID helpers
# ---------------------------------------------------------------------------

def embedded_oids(path, arc=ARC, openssl_bin='openssl'):
    """Return the sorted, unique arc OIDs a DER file embeds.

    Runs ``openssl asn1parse`` with a null cnf (keeps the hybrid provider out
    of the picture).  Plain libcrypto has no names for the arc, so asn1parse
    prints these OIDs numerically.
    """
    try:
        out = subprocess.run(
            [openssl_bin, 'asn1parse', '-inform', 'DER', '-in', path],
            capture_output=True, text=True,
            env={**os.environ, 'OPENSSL_CONF': os.devnull},
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    pat = re.compile(r'OBJECT\s*:\s*(' + arc + r')$', re.MULTILINE)
    return sorted(set(pat.findall(out)))


def oid_check(path, expected_oid, arc=ARC, openssl_bin='openssl'):
    """Check that *path* embeds exactly the single arc OID *expected_oid*.

    Returns ``None`` if coherent, or an error-message string if not.
    """
    emb = embedded_oids(path, arc, openssl_bin)
    if emb == [expected_oid]:
        return None
    base = os.path.basename(path)
    if not emb:
        return (f'{base}: no arc OID found inside (unparseable DER, or this '
                f'OpenSSL prints the arc OIDs by name), expected {expected_oid}')
    return (f'{base} embeds [{" ".join(emb)}] instead of its filename '
            f'OID {expected_oid}')


def report_oid(family, peer, oid):
    """Append a ``<family> <peer> <oid>`` line to ``$PQC_OID_REPORT``, if set."""
    path = os.environ.get('PQC_OID_REPORT', '')
    if path:
        with open(path, 'a') as f:
            f.write(f'{family} {peer} {oid}\n')


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
# PqcCorpus -- shared scaffolding for the three interop scripts
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
        p.add_argument('--outdir', default='',
                        help=f'generate output dir (default: <module-dir>/{self.outname})')
        p.add_argument('--keep', action='store_true',
                        help='keep the temp work dir')
        p.add_argument('--strict', action='store_true',
                        default=os.environ.get('STRICT', '0') == '1',
                        help='unreachable / empty peer is FAIL, not SKIP')
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
        self.outdir = args.outdir
        self.keep = args.keep
        self.strict = args.strict
        self.mode = args.mode
        return args

    # ---- setup -------------------------------------------------------------

    def setup(self):
        """Create workdir, write cnf, guard providers.  Call after parse_args."""
        # Absolutize module_dir
        if os.path.isdir(self.module_dir):
            self.module_dir = os.path.realpath(self.module_dir)
        if not self.outdir:
            self.outdir = os.path.join(self.module_dir, self.outname)

        # Library path
        if self.openssl_libpath:
            ld = os.environ.get('LD_LIBRARY_PATH', '')
            parts = [self.openssl_libpath] + ([ld] if ld else [])
            os.environ['LD_LIBRARY_PATH'] = ':'.join(parts)
        os.environ['OPENSSL_MODULES'] = self.module_dir

        # Version gate (CMS needs 3.6.0+)
        if self.version_gate_fn:
            self.version_gate_fn(self)

        # Color
        self._use_color = sys.stdout.isatty()

        # Provider module
        hybrid_path = os.path.join(self.module_dir, f'hybrid.{self.soext}')
        if not os.path.isfile(hybrid_path):
            print(f'hybrid.{self.soext} not found in {self.module_dir} '
                  f'-- build the provider first', file=sys.stderr)
            sys.exit(1)

        # Workdir + cnf
        self.workdir = tempfile.mkdtemp()
        self.cnf = os.path.join(self.workdir, 'hybrid.cnf')
        with open(self.cnf, 'w') as f:
            f.write(f"""\
openssl_conf = c
[c]
providers = p
[p]
default = d
hybrid = x
[d]
activate = 1
[x]
module = {self.module_dir}/hybrid.{self.soext}
activate = 1
""")

        # Guard: provider must actually load
        out = self.oss('list', '-providers', check=False, capture=True)
        if 'name: hybrid-provider' not in (out.stdout or ''):
            ver = self._openssl_version()
            print(f'ERROR: hybrid provider present at {hybrid_path} but did not',
                  file=sys.stderr)
            print(f'       activate under {self.openssl_bin} ({ver}).',
                  file=sys.stderr)
            print(f'       Likely an ABI/libcrypto mismatch or a missing '
                  f'component dependency.', file=sys.stderr)
            sys.exit(1)

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
        """A peer with nothing comparable: SKIP by default, FAIL under --strict."""
        if self.strict:
            self.no(msg)
        else:
            self.note(msg)

    def hdr(self, msg):
        print()
        print(f'== {msg} ==')

    # ---- subprocess --------------------------------------------------------

    def oss(self, *args, check=True, capture=False):
        """Run openssl with the hybrid cnf."""
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
        misreads it as cert extensions).
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
        return True

    # ---- verify loop -------------------------------------------------------

    def verify_all(self, header, verify_peer_fn):
        """Run *verify_peer_fn* for each peer; print header + summary."""
        self.hdr(header)
        ver = self._openssl_version()
        label = 'corpus' if self.zip_prefix == 'cms' else 'round'
        tag = f'{self.zip_prefix}_{self.round}' if self.zip_prefix == 'cms' \
              else self.round
        print(f'  {label}: {tag}   openssl: {ver}')
        voids = os.path.join(self.workdir, 'verified_oids')
        open(voids, 'w').close()
        for peer in self.peers.split():
            verify_peer_fn(self, peer)
        if os.path.getsize(voids) > 0:
            with open(voids) as f:
                n = len(set(f.read().split()))
            denom = '18' if self.kind == 'certs' else '12'
            noun = ('composite' if self.kind == 'certs'
                    else 'composite-KEM')
            print(f'  distinct {noun} OIDs verified from >=1 peer: {n}/{denom}')

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
