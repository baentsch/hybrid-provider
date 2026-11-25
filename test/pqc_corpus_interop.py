#!/usr/bin/env python3
# Copyright 2026 hybrid-provider contributors
# SPDX-License-Identifier: Apache-2.0
#
# pqc_corpus_interop.py -- one capability-driven interop tool for the IETF
# Hackathon PQC certificate corpus (github.com/IETF-Hackathon/pqc-certificates),
# the multi-vendor X.509/CMS interop set.  Replaces the three per-family scripts
# (sig certs / composite-KEM decaps / composite-KEM CMS) with a single walk.
#
# Instead of filtering the corpus to a hand-curated OID arc, it walks EVERY
# artifact of EVERY peer and asks one question per artifact: "can anything
# currently loaded handle this?".  The answer partitions each algorithm OID:
#
#   ours        the hybrid provider serves this OID (discovered at runtime by
#               enumerating its algs + reading the OID its own keys embed).
#               A corpus artifact for an OID we serve that we CANNOT
#               verify/decapsulate/decrypt is a real FAIL (regression / drift).
#               The LAMPS composite arc is must-pass too, so a brand-new
#               composite OID the corpus ships is surfaced before we serve it
#               (--strict; the drift script relies on this).
#   qualified   not ours, but a loaded component provider (default / oqs / ...)
#               handles it -> interop with that component confirmed.  Loading
#               oqsprovider thus qualifies its plain-PQ algs against the corpus
#               for free -- no arc to curate.
#   not-served  none of the providers WE loaded can complete the operation.  The
#               artifact is of course valid -- the peer that produced it ran some
#               provider we have not loaded (or one that assigns the algorithm a
#               different OID, e.g. a research-KEM OID oqsprovider cannot
#               (de)serialize); so this is informational, not a fault -- load that
#               provider and the OID becomes "qualified".  (The corpus ships ~30
#               families; e.g. McEliece when no such provider is loaded.)
#
# Modes:
#   verify    (default) read every peer's artifacts and classify (above).
#   generate  write THIS provider's composite artifacts (sig + KEM + CMS) in the
#             corpus r5/cms layout and self-verify -- the submission set, and the
#             source of "our OIDs" for scripts/check-pqc-certs-drift.sh.
#   all       verify, then generate.
#
# Providers to load are chosen with --providers (default "default hybrid").  CMS
# KEMRI artifacts need OpenSSL 3.6.0+; on older OpenSSL that artifact type is
# skipped (sig + KEM still run).  Opt-in harness: needs network + the external
# corpus; not wired into ctest.

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile

# The sibling helper module is found by prepending this file's directory to
# sys.path first, so the import deliberately follows a statement; "noqa: E402"
# silences flake8's "module import not at top of file" for exactly that reason.
sys.path.insert(0, os.path.dirname(__file__))
from pqc_corpus_common import (  # noqa: E402  (import must follow sys.path setup)
    ARC, KEMRI_GLOB, N_COMPOSITE_KEM_OIDS, N_COMPOSITE_SIG_OIDS,
    PLAINTEXT_FILE, RAW_BASE, SUF_CT, SUF_EE, SUF_KEMRI, SUF_PRIV, SUF_PUB,
    SUF_SS, SUF_TA, SUF_TA_PEM, _objects, file_oid, files_equal, oid_check,
    privs, report_oid, soext)

# Peers that publish each artifact kind.  Classification is arc-free/capability-
# driven, but *which peers* ship a given kind is curated: it mirrors the corpus
# (not every peer ships KEM vectors or well-formed CMS KEMRI), and it keeps a
# third party's mislabeled blob in a kind it does not really publish from
# reddening our gate.  --peers (or $PEERS) overrides all three at once.
SIG_PEERS = ('bc carl-redhound cht composite-crypto composite-sigs-ref-impl '
             'crypto4a cryptonext entrust entrust-pkihub leancrypto '
             'openssl-composite-preliminary-impl safelogic')
KEM_PEERS = 'composite-kem-ref-impl bc cht crypto4a cryptonext entrust'
CMS_PEERS = 'composite-crypto bc'

# Our generated CMS EnvelopedData payload.
PLAINTEXT = os.environ.get('PLAINTEXT', 'Hello, World!')

_ARC_RE = re.compile(ARC + r'$')


class Corpus:
    """State + helpers for the unified corpus interop tool."""

    def __init__(self):
        self.openssl_bin = 'openssl'
        self.openssl_libpath = ''
        self.module_dir = ''
        self.peers = ''             # '' = per-kind lists; non-empty overrides
        self.round = 'r5'           # certs zip round
        self.cms_ver = 'v3'         # cms zip version
        self.providers = 'default hybrid'
        self.propq = ''
        self.provider_params = []   # "name:key=value"
        self.csv_path = ''
        self.compat_dir = ''
        self.csv_consumer = ''
        self.outdir = ''
        self.outname = 'pqc-corpus-artifacts'
        self.keep = False
        self.workdir_opt = ''
        self.verbose = False
        self.strict = False
        self.mode = 'verify'
        self.soext = soext()

        self.workdir = ''
        self.cnf = ''
        self.ver = (0, 0)           # openssl (major, minor)
        self.ours = set()           # OIDs the hybrid provider serves
        self.pass_count = 0
        self.fail_count = 0
        self.skip_count = 0
        self._use_color = False
        # Aggregated per-OID state for the coverage report / CSV:
        #   oid -> {'fam','ship':set(peers),'served':set(peers),'wrong':bool}
        self._oidstat = {}
        self._fetch_cache = {}
        self._compat_files = {}     # csv path -> set of rows already written
        self._component_cache = None  # lazily-built oid -> [component names]

    # ---- CLI ---------------------------------------------------------------

    def parse_args(self, argv=None):
        repo = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        p = argparse.ArgumentParser(
            description='Capability-driven pqc-certificates corpus interop.',
            formatter_class=argparse.RawDescriptionHelpFormatter)
        p.add_argument('--openssl', default=os.environ.get('OPENSSL_BIN', 'openssl'))
        p.add_argument('--libpath', default=os.environ.get('OPENSSL_LIBPATH', ''))
        p.add_argument('--module-dir',
                       default=os.environ.get('MODULE_DIR',
                                              os.path.join(repo, 'build')))
        p.add_argument('--peers', default=os.environ.get('PEERS', ''),
                       help='override the per-kind peer lists (space-separated)')
        p.add_argument('--round', default=os.environ.get('ROUND', 'r5'),
                       help='certs artifact round (default: %(default)s)')
        p.add_argument('--cms-version', default=os.environ.get('VER', 'v3'),
                       help='cms artifact version (default: %(default)s)')
        p.add_argument('--providers',
                       default=os.environ.get('PQC_PROVIDERS', 'default hybrid'),
                       help='providers to load: "name" or "name=/path/module" '
                            'each (default: %(default)s)')
        p.add_argument('--propquery', dest='propq',
                       default=os.environ.get('PQC_PROPQ', ''),
                       help='default property query, e.g. "?provider=oqsprovider"')
        p.add_argument('--provider-param', action='append', default=[],
                       metavar='NAME:KEY=VAL',
                       help='extra provider config param (repeatable), e.g. '
                            'oqsprovider:Groups=... ')
        p.add_argument('--csv', dest='csv_path', default=os.environ.get('PQC_CSV', ''),
                       help='write the per-OID coverage table to this CSV path')
        p.add_argument('--compat-csv', dest='compat_dir',
                       default=os.environ.get('PQC_COMPAT_CSV', ''),
                       help="also write the corpus's compatMatrices submission "
                            'CSVs (<peer>_<consumer>.csv) under this dir')
        p.add_argument('--csv-consumer', dest='csv_consumer',
                       default=os.environ.get('PQC_CSV_CONSUMER', ''),
                       help='consumer name in the compatMatrices file names '
                            '(default: last --providers entry other than '
                            'base/default)')
        p.add_argument('--outdir', default='',
                       help='generate output dir (default: <module-dir>/%s)'
                            % self.outname)
        p.add_argument('-v', '--verbose', action='store_true',
                       help='log every artifact of every peer as it is probed '
                            '(the per-artifact trail behind the summary)')
        p.add_argument('--keep', action='store_true', help='keep the temp work dir')
        p.add_argument('--workdir', default=os.environ.get('WORKDIR', ''),
                       help='scratch dir to use instead of a fresh temp dir '
                            '(created if absent, and never auto-removed); the '
                            'default is mkdtemp under $TMPDIR')
        p.add_argument('--strict', action='store_true',
                       default=os.environ.get('STRICT', '0') == '1',
                       help='unreachable peer, or an OID we serve / a composite '
                            'OID we cannot read, is FAIL not SKIP')
        p.add_argument('mode', nargs='?', default='verify',
                       choices=['verify', 'generate', 'all'])
        a = p.parse_args(argv)
        self.openssl_bin = a.openssl
        self.openssl_libpath = a.libpath
        self.module_dir = a.module_dir
        self.peers = a.peers
        self.round = a.round
        self.cms_ver = a.cms_version
        self.providers = a.providers
        self.propq = a.propq
        self.provider_params = a.provider_param
        self.csv_path = a.csv_path
        self.compat_dir = a.compat_dir
        self.csv_consumer = a.csv_consumer
        self.outdir = a.outdir
        self.keep = a.keep
        self.workdir_opt = a.workdir
        self.verbose = a.verbose
        self.strict = a.strict
        self.mode = a.mode

    # ---- providers ---------------------------------------------------------

    def has_provider(self, name):
        return any(e.split('=', 1)[0] == name for e in self.providers.split())

    def _write_cnf(self, hybrid_path):
        """Generate the provider cnf from --providers / --propquery / params."""
        names = [e.split('=', 1)[0] for e in self.providers.split()]
        lines = ['openssl_conf = c', '[c]', 'providers = p']
        if self.propq:
            lines.append('alg_section = a')
        lines.append('[p]')
        lines += [f'{n} = s_{n}' for n in names]
        # Per-provider sections (module path + activate + any extra params).
        extra = {}
        for pp in self.provider_params:          # "name:key=value"
            name, kv = pp.split(':', 1)
            extra.setdefault(name, []).append(kv.replace('=', ' = ', 1))
        for e in self.providers.split():
            name = e.split('=', 1)[0]
            mod = e.split('=', 1)[1] if '=' in e else ''
            if name == 'hybrid' and not mod:
                mod = hybrid_path
            lines.append(f'[s_{name}]')
            if mod:
                lines.append(f'module = {mod}')
            lines.append('activate = 1')
            lines += extra.get(name, [])
        if self.propq:
            lines += ['[a]', f'default_properties = {self.propq}']
        with open(self.cnf, 'w') as f:
            f.write('\n'.join(lines) + '\n')

    # ---- setup -------------------------------------------------------------

    def setup(self):
        if os.path.isdir(self.module_dir):
            self.module_dir = os.path.realpath(self.module_dir)
        if not self.outdir:
            self.outdir = os.path.join(self.module_dir, self.outname)
        if self.openssl_libpath:
            ld = os.environ.get('LD_LIBRARY_PATH', '')
            os.environ['LD_LIBRARY_PATH'] = ':'.join(
                [self.openssl_libpath] + ([ld] if ld else []))
        os.environ['OPENSSL_MODULES'] = self.module_dir
        self._use_color = sys.stdout.isatty()
        self.ver = self._openssl_version_tuple()

        hybrid_path = os.path.join(self.module_dir, f'hybrid.{self.soext}')
        if self.has_provider('hybrid') and not os.path.isfile(hybrid_path):
            sys.exit(f'hybrid.{self.soext} not found in {self.module_dir} '
                     f'-- build the provider first')

        if self.workdir_opt:
            self.workdir = os.path.abspath(self.workdir_opt)
            os.makedirs(self.workdir, exist_ok=True)
            self.keep = True            # never auto-remove a user-named dir
        else:
            self.workdir = tempfile.mkdtemp()   # honours $TMPDIR
        self.cnf = os.path.join(self.workdir, 'providers.cnf')
        self._write_cnf(hybrid_path)

        # Guard: OpenSSL silently drops a cnf provider that fails to load.
        listed = self.oss('list', '-providers', check=False, capture=True).stdout or ''
        active = {ln.strip() for ln in listed.splitlines()
                  if ln.startswith('  ') and not ln.startswith('   ')}
        for e in self.providers.split():
            name = e.split('=', 1)[0]
            if name not in active:
                sys.exit(f"ERROR: provider '{name}' did not activate under "
                         f"{self.openssl_bin} ({self._openssl_version()}). "
                         f"Wrong module path, ABI/libcrypto mismatch, or a "
                         f"missing component dependency.")

        # compatMatrices consumer defaults to the last loaded provider that is
        # not base/default (the distinguishing one, e.g. hybrid or oqsprovider).
        if self.compat_dir and not self.csv_consumer:
            names = [e.split('=', 1)[0] for e in self.providers.split()]
            cand = [n for n in names if n not in ('base', 'default')]
            self.csv_consumer = (cand or names or ['hybrid'])[-1]

    def _compat_row(self, peer, fam, zip_tag, oid, typ, ok):
        """Append one corpus compatMatrices row (deduped), creating the file.

        <compat-dir>/artifacts_<zip_tag>/<peer>_<consumer>.csv; certs carry a
        type column (cert/priv/seed/expandedkey/both/consistent), cms does not.
        """
        f = os.path.join(self.compat_dir, f'artifacts_{zip_tag}',
                         f'{peer}_{self.csv_consumer}.csv')
        yn = 'Y' if ok else 'N'
        row = f'{oid},{yn}' if fam == 'cms' else f'{oid},{typ},{yn}'
        seen = self._compat_files.get(f)
        if seen is None:
            os.makedirs(os.path.dirname(f), exist_ok=True)
            header = ('key_algorithm_oid,test_result' if fam == 'cms'
                      else 'key_algorithm_oid,type,test_result')
            with open(f, 'w') as fh:
                fh.write(header + '\n')
            seen = self._compat_files[f] = set()
        if row not in seen:
            seen.add(row)
            with open(f, 'a') as fh:
                fh.write(row + '\n')

    def cms_enabled(self):
        """CMS KEMRI needs OpenSSL 3.6.0+ (KEMRI landed in 3.6, PR 27681)."""
        return self.ver >= (3, 6)

    def cleanup(self):
        if not self.keep and self.workdir and os.path.isdir(self.workdir):
            shutil.rmtree(self.workdir, ignore_errors=True)

    # ---- output ------------------------------------------------------------

    def _c(self, code, text):
        return f'\033[{code}m{text}\033[0m' if self._use_color else text

    def ok(self, msg):
        print(f'  {self._c(32, "PASS")}  {msg}'); self.pass_count += 1

    def no(self, msg):
        print(f'  {self._c(31, "FAIL")}  {msg}'); self.fail_count += 1

    def note(self, msg):
        print(f'  {self._c(33, "SKIP")}  {msg}'); self.skip_count += 1

    def miss(self, msg):
        self.no(msg) if self.strict else self.note(msg)

    def hdr(self, msg):
        print(); print(f'== {msg} ==')

    # ---- subprocess --------------------------------------------------------

    def oss(self, *args, check=True, capture=False):
        env = {**os.environ, 'OPENSSL_CONF': self.cnf}
        kw = dict(env=env)
        if capture:
            kw['capture_output'] = True; kw['text'] = True
        else:
            kw['stdout'] = subprocess.DEVNULL; kw['stderr'] = subprocess.DEVNULL
        if check:
            kw['check'] = True
        try:
            return subprocess.run([self.openssl_bin] + list(args), **kw)
        except (subprocess.CalledProcessError, OSError):
            if check:
                raise
            return subprocess.CompletedProcess(args, 1, stdout='', stderr='')

    def oss_ok(self, *args):
        try:
            self.oss(*args, check=True); return True
        except (subprocess.CalledProcessError, OSError):
            return False

    def oss_output(self, *args):
        r = self.oss(*args, check=False, capture=True)
        return r.stdout if r.returncode == 0 else ''

    def ossp(self, subcmd, *args):
        """Null cnf + explicit -provider default/hybrid (for generate's x509 -new)."""
        env = {**os.environ, 'OPENSSL_CONF': os.devnull}
        try:
            return subprocess.run(
                [self.openssl_bin, subcmd, '-provider', 'default',
                 '-provider', 'hybrid'] + list(args),
                env=env, capture_output=True, text=True, check=True)
        except (subprocess.CalledProcessError, OSError):
            return subprocess.CompletedProcess(args, 1, stdout='', stderr='')

    def ossp_ok(self, subcmd, *args):
        return self.ossp(subcmd, *args).returncode == 0

    def _openssl_version(self):
        try:
            return subprocess.run([self.openssl_bin, 'version'],
                                  capture_output=True, text=True).stdout.strip()
        except OSError:
            return 'unknown'

    def _openssl_version_tuple(self):
        m = re.match(r'OpenSSL (\d+)\.(\d+)\.', self._openssl_version())
        return (int(m.group(1)), int(m.group(2))) if m else (0, 0)

    # ---- peer fetch --------------------------------------------------------

    def fetch_peer(self, peer, zip_prefix, tag):
        """Download + unzip a peer's artifact zip (cached per peer/prefix/tag).

        Returns the unpacked dir, or None if the zip is absent/unreachable.  sig
        and kem share the one 'certs' zip, so the cache fetches it once.
        """
        key = (peer, zip_prefix, tag)
        if key in self._fetch_cache:
            return self._fetch_cache[key]
        zf = os.path.join(self.workdir, f'{peer}-{zip_prefix}.zip')
        d = os.path.join(self.workdir, peer, zip_prefix)
        url = f'{RAW_BASE}/{peer}/artifacts_{zip_prefix}_{tag}.zip'
        result = None
        try:
            r = subprocess.run(['curl', '-fsSL', url, '-o', zf],
                               capture_output=True, timeout=60)
            if r.returncode == 0 and os.path.isfile(zf) \
                    and os.path.getsize(zf) > 0:
                os.makedirs(d, exist_ok=True)
                subprocess.run(['unzip', '-qo', zf, '-d', d], capture_output=True)
                result = d
        except (OSError, subprocess.TimeoutExpired):
            result = None
        self._fetch_cache[key] = result
        return result

    # ---- runtime "ours" discovery -----------------------------------------

    def _list_algs(self, flag, provider):
        """Usable `genpkey -algorithm` names a provider lists for *flag*.

        Handles both the plain form (``name @ provider``) and the brace-alias
        form the default provider uses (``{ oid, id-foo, FOO, FOO2 } @ provider``),
        picking a readable alias (not the bare OID) for each.
        """
        names = []
        for ln in self.oss_output('list', flag).splitlines():
            if '@' not in ln:
                continue
            spec, _, prov = ln.rpartition('@')
            if prov.strip() != provider:
                continue
            spec = spec.strip()
            if spec.startswith('{'):
                toks = [t.strip() for t in spec.strip('{} ').split(',') if t.strip()]
                cand = [t for t in toks if not re.fullmatch(r'[0-9.]+', t)]
                name = next((t for t in cand if not t.startswith('id-')),
                            (cand or toks or [''])[0])
            else:
                name = spec.split()[0] if spec.split() else ''
            if name:
                names.append(name)
        return names

    def _oids_served_by(self, name):
        """OIDs a loaded provider serves, read from the keys it generates.

        For each of its signature + KEM algorithms, generate a key and read the
        OID its SPKI embeds -- the same OID the corpus names artifacts by.  This
        is provider-name based (not a property query), so it is robust across
        providers (a mandatory `provider=` query does not reliably select some
        third-party decoders).
        """
        oids = set()
        for flag in ('-signature-algorithms', '-kem-algorithms'):
            for alg in self._list_algs(flag, name):
                key = os.path.join(self.workdir, f'map-{name}-{alg}.key')
                pub = key + '.pub'
                if not self.oss_ok('genpkey', '-algorithm', alg, '-out', key):
                    continue
                if not self.oss_ok('pkey', '-in', key, '-pubout',
                                   '-outform', 'DER', '-out', pub):
                    continue
                oid = next(_objects(pub, self.openssl_bin), '')
                if oid:
                    oids.add(oid)
        return oids

    def discover_ours(self):
        """OIDs the hybrid provider serves (the must-pass set)."""
        if self.has_provider('hybrid'):
            self.ours = self._oids_served_by('hybrid')

    def must_pass(self, oid):
        """Artifacts we are obliged to read: anything we serve, plus (in strict
        mode) the whole composite arc, so a new composite OID the corpus ships
        FAILs the read even before COMPOSITE_*_LIST catches up."""
        return oid in self.ours or (self.strict and bool(_ARC_RE.fullmatch(oid)))

    # ---- per-artifact probes ----------------------------------------------
    # Each returns (served, detail, rows).  "served" is the primary verdict: the
    # operation completed to the right answer (not merely that a key parsed) --
    # it drives ours/qualified/not-served.  rows is the per-key-form detail, a
    # list of (type, ok): ok True/False, or None when a shipped key form does not
    # load (a SKIP -- peers also ship encodings the spec does not define).  It
    # feeds the compatMatrices CSV and the key-form checks (see _walk_kind).

    @staticmethod
    def _key_form(priv):
        """Name a private-key form from its filename (corpus convention)."""
        b = os.path.basename(priv)
        for tag, name in (('_seed', 'seed'), ('_expandedkey', 'expandedkey'),
                          ('_both', 'both')):
            if b.endswith(tag + SUF_PRIV):
                return name
        return 'priv'

    def _sign_check(self, priv, pub_pem):
        """Sign a fixed message with PRIV (DER) and verify it under PUB_PEM.

        A key form can derive the right public key yet carry a broken expanded
        secret, so this is the corpus's own per-form test (issue #169).
        """
        msg = os.path.join(self.workdir, 'sign-check.msg')
        sig = os.path.join(self.workdir, 'sign-check.sig')
        if not os.path.isfile(msg):
            with open(msg, 'w') as f:
                f.write('pqc-certificates key-form sign check\n')
        return (self.oss_ok('pkeyutl', '-sign', '-inkey', priv, '-keyform',
                            'DER', '-rawin', '-in', msg, '-out', sig)
                and self.oss_ok('pkeyutl', '-verify', '-pubin', '-inkey',
                                pub_pem, '-rawin', '-in', msg, '-sigfile', sig))

    def probe_sig(self, ta):
        pem = ta + '.pem'
        if not self.oss_ok('x509', '-inform', 'DER', '-in', ta, '-out', pem):
            pem = ta
        served = self.oss_ok('verify', '-no_check_time', '-CAfile', pem, pem)
        rows = [('cert', served)]
        # Key forms: each shipped private key must load, yield the trust anchor's
        # public key ("consistent") and sign a message that verifies under it --
        # exercising the PKCS#8 decoder + signer the cert verify never touches.
        pub = self.oss_output('x509', '-in', pem, '-noout', '-pubkey')
        pub_pem = os.path.join(self.workdir, 'ta-pub.pem')
        with open(pub_pem, 'w') as f:
            f.write(pub)
        consistent = None
        for priv in privs(ta[:-len(SUF_TA)]):
            form = self._key_form(priv)
            if not self.oss_ok('pkey', '-in', priv, '-inform', 'DER', '-noout'):
                rows.append((form, None))
                continue
            kpub = self.oss_output('pkey', '-in', priv, '-inform', 'DER', '-pubout')
            pub_ok = bool(kpub) and kpub == pub
            consistent = pub_ok if consistent is None else (consistent and pub_ok)
            rows.append((form, self._sign_check(priv, pub_pem)))
        if consistent is not None:
            rows.append(('consistent', consistent))
        return served, ('' if served else 'not verified'), rows

    def probe_kem(self, ss):
        base = ss[:-len(SUF_SS)]
        ct = base + SUF_CT
        forms = privs(base)
        if not forms or not os.path.isfile(ct):
            return False, f'missing {SUF_PRIV} / {SUF_CT}', []
        served = False
        rows = []
        consistent = None
        for priv in forms:
            form = self._key_form(priv)
            if not self.oss_ok('pkey', '-in', priv, '-inform', 'DER', '-noout'):
                rows.append((form, None))
                continue
            out = os.path.join(self.workdir, os.path.basename(priv) + '.out')
            ok = (self.oss_ok('pkeyutl', '-decap', '-inkey', priv, '-keyform',
                              'DER', '-in', ct, '-secret', out)
                  and files_equal(out, ss))
            rows.append((form, ok))
            consistent = ok if consistent is None else (consistent and ok)
            served = served or ok
        if consistent is not None:
            rows.append(('consistent', consistent))
        return served, ('' if served else 'no key form decapsulated'), rows

    def probe_cms(self, blob, expected):
        base = blob.split('_kemri_', 1)[0]   # strip any recipient variant suffix
        forms = privs(base)
        if not forms or not expected:
            return False, f'missing {SUF_PRIV} / {PLAINTEXT_FILE}', []
        served = False
        rows = []
        for priv in forms:
            form = self._key_form(priv)
            if not self.oss_ok('pkey', '-in', priv, '-inform', 'DER', '-noout'):
                rows.append((form, None))
                continue
            out = os.path.join(self.workdir, os.path.basename(priv) + '.pt')
            ok = (self.oss_ok('cms', '-decrypt', '-inform', 'DER', '-in', blob,
                             '-inkey', priv, '-keyform', 'DER', '-out', out)
                  and files_equal(out, expected))
            rows.append((form, ok))
            served = served or ok
        return served, ('' if served else 'no key form decrypted'), rows

    # ---- verify ------------------------------------------------------------

    def _classify(self, fam, peer, oid, src, served, detail):
        """Record one probed artifact and emit its FAIL line if it is one."""
        report_oid(fam, peer, oid)
        st = self._oidstat.setdefault(
            oid, {'fam': fam, 'ship': set(), 'served': set(), 'wrong': False})
        st['ship'].add(peer)
        base = os.path.basename(src)
        if served:
            st['served'].add(peer)
            return
        # Not served.  Must-pass -> FAIL; otherwise it is simply not-served.
        if self.must_pass(oid):
            st['wrong'] = True
            self.no(f'{peer}: {oid} ({base}) {detail} '
                    f'[served by hybrid: must read]')

    def _walk_kind(self, peer, d, fam, zip_tag, pattern, probe, expected=None):
        """Probe every artifact of one kind under a peer dir.  Returns counts."""
        n = ours = qual = unserved = 0
        for art in sorted(glob.glob(os.path.join(d, '**', pattern),
                                    recursive=True)):
            oid = file_oid(art)
            if not oid:
                continue
            n += 1
            # Coherence only where we must read it: a mislabeled artifact we are
            # obliged to verify is drift; for ones we only qualify, the label is
            # the peer's business.  The OID lives in a DER file, which differs by
            # kind (the cert / the KEMRI blob / the KEM private key -- never the
            # raw _ss.bin shared secret).
            if self.must_pass(oid) and _ARC_RE.fullmatch(oid):
                why = next((w for w in
                            (oid_check(cf, oid, ARC, self.openssl_bin)
                             for cf in self._coherence_files(fam, art)) if w),
                           None)
                if why:
                    self.no(f'{peer}: {why}')
                    report_oid(fam, peer, oid)
                    continue
            served, detail, rows = (probe(art, expected) if expected is not None
                                    else probe(art))
            self._classify(fam, peer, oid, art, served, detail)
            self._key_forms(peer, fam, zip_tag, oid, served, rows)
            if served and oid in self.ours:
                ours += 1
                verdict = 'PASS (ours)'
            elif served:
                qual += 1
                comp = self._component_of(oid) if self.verbose else 'component'
                verdict = f'PASS (component: {comp})'
            elif self.must_pass(oid):
                verdict = f'FAIL ({detail})'
            else:
                unserved += 1
                verdict = f'skip (not served: {detail})' if detail \
                    else 'skip (not served)'
            if self.verbose:
                print(f'    {peer} [{fam}] {oid} {os.path.basename(art)}'
                      f'  ->  {verdict}')
        return n, ours, qual, unserved

    def _key_forms(self, peer, fam, zip_tag, oid, served, rows):
        """Apply per-key-form results: compatMatrices CSV + FAIL/SKIP policy.

        A loadable key form that fails its check (wrong public key, failed
        signature, wrong secret/plaintext) is a FAIL for an artifact we must read.
        A form that does not load, or a failure on an artifact we only qualify, is
        informational -- the component's business -- printed only with -v and not
        counted as a SKIP (those count real environment gaps, not per-form detail).
        """
        for typ, ok in rows:
            if self.compat_dir and ok is not None:
                self._compat_row(peer, fam, zip_tag, oid, typ, ok)
            if typ == 'cert' or ok:          # primary handled by _classify
                continue
            label = f'{peer}: {oid} key form {typ}' if typ != 'consistent' \
                else f'{peer}: {oid} key forms inconsistent with trust anchor'
            if ok is None:
                if self.verbose:
                    print(f'    .. {peer}: {oid} key form {typ} not loadable')
            elif self.must_pass(oid):
                self.no(label + ' failed its check')
            elif self.verbose:
                print(f'    .. {label} not handled by a component')

    # Artifact kinds: name, zip prefix, tag source, glob, probe, default peers,
    # minimum OpenSSL.  sig + kem share the 'certs' zip; cms is its own.
    def _kinds(self):
        return (
            ('sig', 'certs', self.round, '*' + SUF_TA,
             self.probe_sig, SIG_PEERS, (0, 0)),
            ('kem', 'certs', self.round, '*' + SUF_SS,
             self.probe_kem, KEM_PEERS, (0, 0)),
            ('cms', 'cms', self.cms_ver, KEMRI_GLOB,
             self.probe_cms, CMS_PEERS, (3, 6)),
        )

    def verify(self):
        self.hdr('Read/verify: pqc-certificates corpus by capability (no arcs)')
        print(f'  corpus: certs {self.round}, cms {self.cms_ver}   '
              f'openssl: {self._openssl_version()}')
        print(f'  providers: {self.providers}'
              + (f'   propquery: {self.propq}' if self.propq else ''))
        print(f'  hybrid serves {len(self.ours)} OIDs (discovered at runtime)')

        for name, prefix, tag, pattern, probe, defpeers, minver in self._kinds():
            if self.ver < minver:
                self.note(f'{name}: skipped (needs OpenSSL '
                          f'{minver[0]}.{minver[1]}.0+, have '
                          f'{self.ver[0]}.{self.ver[1]})')
                continue
            peers = self.peers.split() if self.peers else defpeers.split()
            for peer in peers:
                d = self.fetch_peer(peer, prefix, tag)
                if d is None:
                    self.miss(f'{peer} [{name}]: no artifacts_{prefix}_{tag}.zip '
                              f'(unreachable / absent)')
                    continue
                expected = None
                if name == 'cms':
                    expected = self._cms_expected(d)
                    if not expected:
                        self.miss(f'{peer} [cms]: no {PLAINTEXT_FILE} '
                                  f'(cannot assert content)')
                        continue
                n, o, q, u = self._walk_kind(peer, d, name, f'{prefix}_{tag}',
                                             pattern, probe, expected)
                if n == 0:
                    self.miss(f'{peer} [{name}]: ships no {name} artifacts '
                              f'in {prefix}_{tag}')
                else:
                    self.ok(f'{peer} [{name}]: {o} PASS(ours), '
                            f'{q} PASS(component), {u} not-served (of {n})')

        self._coverage()

    @staticmethod
    def _coherence_files(fam, art):
        """The DER file(s) that must embed the artifact's filename OID."""
        if fam == 'kem':                       # _ss.bin itself carries no OID
            return privs(art[:-len(SUF_SS)])
        return [art]                           # sig cert / cms KEMRI blob

    def _component_names(self):
        """Loaded provider names other than hybrid (the qualification candidates)."""
        return [e.split('=', 1)[0] for e in self.providers.split()
                if e.split('=', 1)[0] != 'hybrid']

    def _component_of(self, oid):
        """Name the loaded component provider(s) that serve a qualified OID.

        Looked up in an OID->provider map built (once, lazily) by asking each
        non-hybrid provider which OIDs its own keys carry -- see _oids_served_by.
        'component' if none maps it (e.g. an OID whose alg the provider lists but
        cannot keygen).  Only called in --verbose, so the map cost is opt-in.
        """
        if self._component_cache is None:
            self._component_cache = {}
            for name in self._component_names():
                for o in self._oids_served_by(name):
                    self._component_cache.setdefault(o, []).append(name)
        return ','.join(self._component_cache.get(oid, [])) or 'component'

    @staticmethod
    def _cms_expected(d):
        f = glob.glob(os.path.join(d, '**', PLAINTEXT_FILE),
                      recursive=True)
        return f[0] if f else ''

    def _coverage(self):
        """Global per-OID partition + composite coverage lines + optional CSV."""
        comp_sig = comp_kem = 0
        n_ours = n_qual = n_unserved = 0
        rows = []
        for oid in sorted(self._oidstat):
            st = self._oidstat[oid]
            is_ours = oid in self.ours
            served = bool(st['served'])
            if served and is_ours:
                status = 'ours'; n_ours += 1
                if _ARC_RE.fullmatch(oid):
                    if st['fam'] == 'sig':
                        comp_sig += 1
                    else:
                        comp_kem += 1
            elif served:
                status = 'qualified'; n_qual += 1
            elif self.must_pass(oid):
                status = 'FAIL'
            else:
                status = 'not-served'; n_unserved += 1
            rows.append((st['fam'], oid, is_ours, len(st['ship']),
                         len(st['served']), status))

        print()
        print(f'  Coverage over {len(self._oidstat)} distinct corpus OIDs:')
        print(f'    served by hybrid (ours):       {n_ours}')
        print(f'    served by a component only:    {n_qual}')
        print(f'    not served by anything loaded: {n_unserved}')
        print(f'  distinct composite OIDs verified: '
              f'sig {comp_sig}/{N_COMPOSITE_SIG_OIDS}, '
              f'kem {comp_kem}/{N_COMPOSITE_KEM_OIDS}')
        if self.csv_path:
            with open(self.csv_path, 'w') as f:
                f.write('family,oid,is_ours,peers_shipping,peers_served,status\n')
                for fam, oid, io, ns, nv, status in rows:
                    f.write(f'{fam},{oid},{int(io)},{ns},{nv},{status}\n')
            print(f'  wrote per-OID CSV: {self.csv_path}')
        if self._compat_files:
            print(f'  wrote {len(self._compat_files)} compatMatrices CSV(s) '
                  f'(consumer={self.csv_consumer}) under {self.compat_dir}')

    # ---- generate ----------------------------------------------------------

    def can_generate(self):
        if self.has_provider('hybrid'):
            return True
        self.note('generate writes hybrid-provider composite artifacts: '
                  'needs hybrid in --providers')
        return False

    def _hybrid_algs(self, flag):
        return self._list_algs(flag, 'hybrid')

    def generate(self):
        if not self.can_generate():
            return
        self.hdr('Generate: hybrid-provider composite artifacts + self-verify')
        os.makedirs(self.outdir, exist_ok=True)
        self._gen_sig()
        self._gen_kem()
        if self.cms_enabled():
            self._gen_cms()
        else:
            self.note('cms generate skipped: needs OpenSSL 3.6.0+')

    def _oid_of(self, der):
        for o in _objects(der, self.openssl_bin):
            if _ARC_RE.fullmatch(o):
                return o
        return ''

    def _gen_sig(self):
        n = p = 0
        for alg in self._hybrid_algs('-signature-algorithms'):
            key = os.path.join(self.workdir, f'{alg}.key')
            crt = os.path.join(self.workdir, f'{alg}.crt')
            der = os.path.join(self.workdir, f'{alg}.crt.der')
            if not self.oss_ok('genpkey', '-algorithm', alg, '-out', key):
                continue
            if not self.oss_ok('req', '-x509', '-key', key, '-subj',
                               f'/CN=hybrid-provider {alg}', '-days', '3650',
                               '-out', crt):
                continue
            if not self.oss_ok('x509', '-in', crt, '-outform', 'DER', '-out', der):
                continue
            oid = self._oid_of(der)
            if not oid:
                continue
            n += 1
            base = os.path.join(self.outdir, f'id-{alg}-{oid}')
            self.oss_ok('x509', '-in', crt, '-outform', 'DER',
                        '-out', base + SUF_TA)
            shutil.copy2(crt, base + SUF_TA_PEM)
            self.oss_ok('pkey', '-in', key, '-outform', 'DER',
                        '-out', base + SUF_PRIV)
            if self.oss_ok('verify', '-no_check_time', '-CAfile',
                           base + SUF_TA_PEM, base + SUF_TA_PEM):
                p += 1
            else:
                self.no(f'{alg} ({oid}) self-verify of generated trust anchor')
        self._gen_report('signature', n, p)

    def _gen_kem(self):
        n = p = 0
        for alg in self._hybrid_algs('-kem-algorithms'):
            key = os.path.join(self.workdir, f'{alg}.kkey')
            pub = os.path.join(self.workdir, f'{alg}.kpub')
            if not self.oss_ok('genpkey', '-algorithm', alg, '-out', key):
                continue
            if not self.oss_ok('pkey', '-in', key, '-pubout', '-outform', 'DER',
                               '-out', pub):
                continue
            oid = self._oid_of(pub)
            if not oid:
                continue
            n += 1
            base = os.path.join(self.outdir, f'id-{alg}-{oid}')
            self.oss_ok('pkey', '-in', key, '-outform', 'DER',
                        '-out', base + SUF_PRIV)
            shutil.copy2(pub, base + SUF_PUB)
            self.oss_ok('pkeyutl', '-encap', '-inkey', pub, '-pubin', '-keyform',
                        'DER', '-out', base + SUF_CT,
                        '-secret', base + SUF_SS)
            chk = os.path.join(self.workdir, f'{alg}.chk')
            if self.oss_ok('pkeyutl', '-decap', '-inkey', base + SUF_PRIV,
                           '-keyform', 'DER', '-in', base + SUF_CT,
                           '-secret', chk) and files_equal(chk, base + SUF_SS):
                p += 1
            else:
                self.no(f'{alg} ({oid}) self-decapsulation of generated ciphertext')
        self._gen_report('composite-KEM', n, p)

    def _gen_cms(self):
        ca_key = os.path.join(self.workdir, 'ca.key')
        ca_crt = os.path.join(self.workdir, 'ca.crt')
        if not self.ossp_ok('genpkey', '-algorithm', 'ED25519', '-out', ca_key) \
                or not self.ossp_ok('x509', '-new', '-key', ca_key, '-subj',
                                    '/CN=hybrid-cms-kem-ca', '-days', '3650',
                                    '-out', ca_crt):
            self.note('cms generate: cannot create Ed25519 CA cert')
            return
        pt = os.path.join(self.outdir, PLAINTEXT_FILE)
        with open(pt, 'w') as f:
            f.write(PLAINTEXT)
        n = p = 0
        for alg in self._hybrid_algs('-kem-algorithms'):
            key = os.path.join(self.workdir, f'{alg}.ckey')
            pub = os.path.join(self.workdir, f'{alg}.cpub')
            if not self.ossp_ok('genpkey', '-algorithm', alg, '-out', key):
                continue
            if not self.ossp_ok('pkey', '-in', key, '-pubout', '-outform', 'DER',
                                '-out', pub):
                continue
            oid = self._oid_of(pub)
            if not oid:
                continue
            n += 1
            base = os.path.join(self.outdir, f'id-{alg}-{oid}')
            self.ossp_ok('pkey', '-in', key, '-outform', 'DER',
                         '-out', base + SUF_PRIV)
            ee = base + SUF_EE
            kemri = base + SUF_KEMRI
            if not self.ossp_ok('x509', '-new', '-force_pubkey', pub, '-CA',
                                ca_crt, '-CAkey', ca_key, '-subj', f'/CN=ee-{oid}',
                                '-days', '365', '-out', ee, '-outform', 'DER') \
                    or not self.ossp_ok('cms', '-encrypt', '-recip', ee,
                                        '-aes-256-cbc', '-binary', '-in', pt,
                                        '-outform', 'DER', '-out', kemri):
                self.no(f'{alg} ({oid}) could not produce EE cert / EnvelopedData')
                continue
            r = self.ossp('cms', '-decrypt', '-inform', 'DER', '-in', kemri,
                          '-inkey', base + SUF_PRIV, '-keyform', 'DER')
            if r.returncode == 0 and r.stdout == PLAINTEXT:
                p += 1
            else:
                self.no(f'{alg} ({oid}) self-decrypt of generated EnvelopedData')
        self._gen_report('composite-KEM CMS', n, p)

    def _gen_report(self, noun, n, p):
        if n == 0:
            self.note(f'no {noun} algorithms available '
                      f'(needs OpenSSL 3.5+ + composite build)')
        else:
            self.ok(f'generated + self-verified {p}/{n} {noun} artifacts '
                    f'-> {self.outdir}')

    # ---- main --------------------------------------------------------------

    def run(self, argv=None):
        self.parse_args(argv)
        self.setup()
        try:
            if self.mode in ('verify', 'all'):
                self.discover_ours()
                self.verify()
            if self.mode in ('generate', 'all'):
                self.generate()
            self.hdr(f'Summary ({self.mode})')
            print(f'  passed: {self.pass_count}   failed: {self.fail_count}'
                  f'   skipped: {self.skip_count}')
            sys.exit(0 if self.fail_count == 0 else 1)
        finally:
            self.cleanup()


if __name__ == '__main__':
    Corpus().run()
