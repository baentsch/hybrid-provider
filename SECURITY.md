# Security Policy

## Status

This provider is an **experimental, AI-generated project** and is **not intended
for production use**. It has not been developed, reviewed or audited to the
standard required for protecting sensitive data, and must not be relied upon to
do so — see the [README](README.md) banner and the
["AI contributions"](CONTRIBUTING.md#ai-contributions) section of
CONTRIBUTING.md.

Accordingly, the project makes **no security guarantees**, operates **no
coordinated-disclosure or embargo process**, and does not request or assign CVEs.

## Reporting a problem

Reports of security-relevant defects are nonetheless welcome — they serve the
project's experimentation and interoperability goals.

- Please open an issue at
  <https://github.com/baentsch/hybrid-provider/issues> describing the problem
  and, where possible, how to reproduce it.
- Because there is no embargo process, do **not** expect confidential handling:
  treat anything you report as public.
- There is no guaranteed response time or fix commitment; triage is best-effort
  by the maintainer(s).

## Scope

This repository implements hybrid and composite constructions on top of
OpenSSL's public EVP API, delegating the underlying cryptographic primitives to
whichever OpenSSL provider supplies them — this is provider-agnostic by design
and any provider may be used (for example the OpenSSL default provider or
oqsprovider). Issues in those upstream components should be reported to the
respective projects rather than here.
