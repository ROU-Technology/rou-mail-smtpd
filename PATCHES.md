# Patch ledger

24 October 2026: planning/provenance only; no upstream Rust source changes yet.

Each later patch records upstream file, behavior/gap, source attribution, regression and native Linux/resource evidence, upstreamability and reversal implications. SMTPD-001 owns the hardening baseline.

24 October dependency baseline: src/core/tls.rs rustls example used
ServerConfig::default(), which does not exist in rustls 0.23. Replaced only
the example with the maintained builder accepting real certificate/key inputs.
Original full test run: 10 doc tests passed / 1 failed; no test weakened.
No protocol runtime change; repeat the full rustls-backend test suite.


24 October — bounded streaming and supervised listener implementation

Based on attributed upstream537eaa2, no Mailin source copied. src/core/stream.rs
uses Tokio fill_buf/consume to enforce line size before allocation and a single
read deadline; strict CRLF replaces newline repair. Full-message allocation was
removed for asynchronous start/chunk/end/abort callbacks in src/core/handler.rs;
reset notifies caller-owned transient state. Default recipients/DATA fail closed.
src/lib.rs uses Tokio JoinSet/Semaphore, finite lifetime/drain and separate TLS
handshake tasks/budget; no serial handshake or handshake panic. src/handler.rs
resets envelopes, refreshes session/handler after STARTTLS, emits CRLF EHLO and
hides/refuses AUTH before TLS. src/constants.rs permits null reverse paths and
anchors supported envelope parameters. Configuration cannot enable unlimited
message/line/connections. Examples/docs use the one current callback API.

Old full-buffer and bare-LF repair tests were replaced with stricter byte-preserving
streaming/size/timeout tests, not deleted to conceal failures. Real TCP/TLS
regressions independently assert raw-byte identity/dot transparency, refusal on
commit failure, no finalise on size/line/callback error, RSET/MAIL/STARTTLS state,
capacity, invalid/stalled TLS alongside healthy clients and finite shutdown.
macOS x86_64: rustls13 unit +13 integration +11 doc tests passed; no TLS13 unit
+11 integration +11 doc tests passed. Linux CI repeats both. Native-TLS backend,
fuzz/property corpus, sustained target-host limits and full gateway/store/product
receipt/scanner acceptance remain open. No production readiness is asserted.

Reversal: stop new listener admission and drain first. Preserve caller-owned
accepted/unknown receipt/store identities; never restore a buffering compatibility
shim or automatically replay external SMTP on downgrade.

Follow-up in the same checkpoint: reject semaphore permit overflow and deadline
Instant overflow during configuration validation (regression cases included).
Write the confirmed end result before calling transient reset cleanup so that
cleanup failure cannot suppress an already confirmed durable acceptance reply.
The final37/35 test suites pass unchanged in scope.
