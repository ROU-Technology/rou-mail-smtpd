# Progress and acceptance

24 October 2026: repository and detailed plan established. No new runtime implementation, dependency adoption, native Linux build, external provider pilot or production acceptance is claimed. Read canonical issues before implementation; record exact checks and remaining gates per increment.

24 October dependency setup: Rust 1.97.1 selected; all locked dependencies
installed and the rustls-backend baseline built on macOS x86_64. Fixed the
upstream rustls example documented in PATCHES.md. Full suite: 14 unit tests
and 11 doc tests passed. These tests do not prove gateway admission hardening
or public production SMTP safety; SMTPD-001 remains open. CI repeats the
locked suite on Linux. No listener or live mail was started.


24 October owner correction: complete library/direct-inbound implementation
contracts now replace generic or research-only coverage. Read the product
library-index.json and direct-inbound-contract.md. Generated local specs and
canonical GitHub bodies were verified against current source; issue state/history
was preserved. Source generation and whitespace checks passed. This increment
changes planning/docs only; no runtime test, DNS, send or deployment occurred.
Previous dependency/build CI does not satisfy these new feature acceptance gates.


24 October runtime checkpoint: bounded streaming SMTP and supervised TCP/TLS
implemented and tested; see PATCHES.md. Local rustls37 total tests and no-TLS35
total tests pass, including real sockets and ephemeral in-memory certificates.
No full-message Vec delivery or old callback compatibility remains. No product/
provider/scanner/store traffic occurred. SMTPD-001 remains in progress: fuzz,
full protocol coverage, native-TLS, sustained Linux target-host and combined
GATE-002/004/005/006 acceptance still required. Linux CI now repeats both builds.

24 October admission/continuity checkpoint: added per-IP connection admission
with guarded release, removed the hardcoded30s reverse-DNS delay by threading
the session deadline, and fixed false/unclean SMTP responses (unconfigured or
untrusted XCLIENT, individually refused RCPT, transient DATA failure, repeated
STARTTLS). Locked suites on macOS x86_64 with Rust1.99: rustls13 unit +21
integration +11 doc; no-TLS13 +19 +11. Local pin1.97.1 is broken in this
environment; CI remains authoritative for1.97.1. No product/store/scanner/DNS
traffic occurred. SMTPD-001 stays open for fuzz/property coverage, native-TLS,
sustained Linux RSS/CPU/fairness, public port25/DNS/TLS and combined
GATE-002/004/005/006 acceptance. Source provenance with upstream SHA-256 hashes
is recorded in docs/source-provenance.md.
