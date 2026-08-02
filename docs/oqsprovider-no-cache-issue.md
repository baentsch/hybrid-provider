# oqsprovider: `no_cache=1` on OpenSSL ≥ 3.5 makes every signature O(provider size)

**Target:** oqs-provider (primary). A secondary OpenSSL enhancement note is at the end.

## Summary

On OpenSSL **≥ 3.5**, oqsprovider returns `*no_cache = 1` from its
`query_operation` callback for the **entire provider**. With `no_cache = 1`,
libcrypto may not cache the fetched methods, so `EVP_DigestSignInit` (which fetches
the key's keymgmt from its provider via `evp_keymgmt_fetch_from_prov` on *every*
call) triggers a full `ossl_method_construct` — O(number of algorithms the provider
registers) — on **every signature operation**.

For fast signatures (Falcon, MAYO, SNOVA, …) this dominates: a single sign that
should take ~0.18 ms takes ~0.36 ms (≈1.9× slower) on 3.5+ vs 3.4. It also slows
every other repeated `EVP_DigestSign*`/`EVP_PKEY` init against oqsprovider keys.

## Root cause

`oqsprov/oqsprov.c`:

```c
static int rt_algo_filter_enabled = 0;                 /* line ~38 */

static const OSSL_ALGORITHM *oqsprovider_query(void *provctx, int operation_id,
                                               int *no_cache) {
    *no_cache = rt_algo_filter_enabled;                /* line ~1273 */
    ...
}

/* in OSSL_provider_init(), guarded by an OpenSSL-version check: */
if (strcmp("3.5.0", ossl_versionp) <= 0) {             /* line ~1407 */
    rt_algo_filter_enabled = 1;
    sk_OPENSSL_STRING_push(rt_disabled_algs, "mldsa44");
}
/* ... repeated for mldsa65/87, slhdsa* ... */
```

The runtime filter exists to hide a handful of algorithms (ML-DSA / SLH-DSA) that
OpenSSL 3.5's default provider now implements natively. But enabling it also sets
`no_cache = 1` for **all** operations and **all** algorithms — including the
hundreds of KEMs/signatures that are *not* filtered. The filtered set
(`rt_disabled_algs`) is **static after `OSSL_provider_init`**, so the query result
is deterministic and there is no correctness reason to disable caching.

## Impact chain (OpenSSL side, for reference — unchanged across 3.4/3.5/main)

`EVP_DigestSignInit_ex` → `do_sigver_init` (`crypto/evp/m_sigver.c`) →
`evp_keymgmt_fetch_from_prov` → `inner_evp_generic_fetch`
(`crypto/evp/evp_fetch.c`): consults the method-store cache, and on miss runs
`ossl_method_construct`. When the provider set `no_cache=1`, the construct result
is not cached, so the next init reconstructs it again.

## Reproduction (no oqs, no hybrid-provider)

A ~150-line self-contained program reproduces it with **zero** third-party
providers: register a tiny in-process provider that exposes one trivial signature
plus ~200 trivial keymgmts (to give a realistic algorithm count), and return
`*no_cache = <argv>` from its `query_operation`. Then time N iterations of
`EVP_MD_CTX_new` + `EVP_DigestSignInit_ex` + `EVP_DigestSign`, once with
`no_cache=0` and once with `no_cache=1` (same binary). No file is kept in-tree —
the mechanism is a one-line change (`*no_cache`), and the numbers below stand on
their own.

Measured (same machine; 200 keymgmts), ms per sign:

| OpenSSL | `no_cache=0` | `no_cache=1` |
|--------|-------------|-------------|
| 3.4.2       | 0.00068 | 0.600 |
| main 4.1-dev | 0.00083 | 0.526 |

`no_cache=1` is ~**700×** slower and is slow on **both** OpenSSL versions — i.e.
OpenSSL's behaviour did not change; only oqsprovider's flag does (0 on 3.4, 1 on
3.5+). Real-world confirmation: with identical liboqs + oqs-provider `main` built
against OpenSSL 3.4 vs main, a standalone `falcon512` sign via `EVP_DigestSign`
goes 0.18 ms → 0.36 ms, and callgrind attributes the delta entirely to
`ossl_method_construct` under `evp_keymgmt_fetch_from_prov`.

## Suggested fix (oqsprovider)

The disabled-algorithm list is fixed once `OSSL_provider_init` returns, so the
query result is cacheable:

- **Simplest:** always return `*no_cache = 0`. The filter still removes the
  disabled algorithms from the returned array; the (stable) result is just allowed
  to be cached.
- **Cleaner:** apply the filter at registration (build the `_rt` arrays once in
  `OSSL_provider_init`) rather than per `query_operation`, and drop
  `rt_algo_filter_enabled` from the `no_cache` decision entirely.

Either restores 3.4-level performance for all non-filtered algorithms on 3.5+.

## Secondary (optional) OpenSSL enhancement

Even with `no_cache=1`, fetching *one* algorithm by name causes
`ossl_method_construct` to build **all** of the provider's algorithms for that
operation into the throwaway store. Constructing only the requested algorithm
would bound the per-fetch cost at O(1) instead of O(provider size). This is an
optimization, not the cause — the primary fix is in oqsprovider.
