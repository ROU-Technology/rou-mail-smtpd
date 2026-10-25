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

24 October — admission, deadline and session-continuity hardening

No upstream source beyond537eaa2 was copied. src/core.rs adds
max_connections_per_ip and max_tls_handshakes with cross-field validation:
neither may exceed max_connections, zero is refused, and auth-required
configurations need at least one mechanism. src/lib.rs enforces a lazy per-IP
admission map behind the global permit and releases the slot through a guard on
every task exit; a refused peer cannot consume the global budget indefinitely.

src/utils/handler.rs::get_remote_host now receives the caller's remaining
deadline instead of a hardcoded30s; reverse DNS cannot outlive the connection
budget. src/handler.rs fixes four state-machine honesty bugs: unconfigured or
untrusted XCLIENT returns502/550 rather than a false250, and peer metadata is
only applied before MAIL; an individually refused RCPT writes its reply and
continues the transaction; a transient DATA failure aborts/resets and keeps the
session when the error is not a transport timeout/IO failure; a refused repeated
STARTTLS writes503 and continues instead of terminating the session.

Regression tests in tests/streaming.rs cover per-IP bound/release, chunk
delivery before terminator, oversized command/DATA line refusal without growth,
XCLIENT refusal/trust ordering, refused recipient continuation, temporary DATA
retry, repeated STARTTLS503, and all prior TCP/TLS cases. Locked rustls suite:
13 unit +21 integration +11 doc =45; no-feature suite:13 unit +19 integration
+11 doc =43, all passing on macOS x86_64 with Rust1.99 (local toolchain pin
1.97.1 is unavailable in this environment; CI keeps1.97.1). These synthetic
socket/transport fixtures do not close gateway, private-store, scanner,
DNS/port25, fuzz or sustained Linux capacity gates. Reversal: drain and stop
new admission first; the per-IP limiter and stricter refusals may be relaxed
only as a whole config change, never by reintroducing unauthenticated relay,
buffering or a compatibility callback shim.
