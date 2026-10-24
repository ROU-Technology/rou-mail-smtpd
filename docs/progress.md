# Progress and acceptance

24 October 2026: repository and detailed plan established. No new runtime implementation, dependency adoption, native Linux build, external provider pilot or production acceptance is claimed. Read canonical issues before implementation; record exact checks and remaining gates per increment.

24 October dependency setup: Rust 1.97.1 selected; all locked dependencies
installed and the rustls-backend baseline built on macOS x86_64. Fixed the
upstream rustls example documented in PATCHES.md. Full suite: 14 unit tests
and 11 doc tests passed. These tests do not prove gateway admission hardening
or public production SMTP safety; SMTPD-001 remains open. CI repeats the
locked suite on Linux. No listener or live mail was started.
