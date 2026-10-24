# Patch ledger

24 October 2026: planning/provenance only; no upstream Rust source changes yet.

Each later patch records upstream file, behavior/gap, source attribution, regression and native Linux/resource evidence, upstreamability and reversal implications. SMTPD-001 owns the hardening baseline.

24 October dependency baseline: src/core/tls.rs rustls example used
ServerConfig::default(), which does not exist in rustls 0.23. Replaced only
the example with the maintained builder accepting real certificate/key inputs.
Original full test run: 10 doc tests passed / 1 failed; no test weakened.
No protocol runtime change; repeat the full rustls-backend test suite.
