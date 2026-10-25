# SMTPD-001: Harden the pinned async SMTP protocol library for the hosted gateway

Status: **in progress**. Phase: **HNR**. Product advancement: HNR-05.

Implementation acceptance remains unproven.

## Flows

- Patch upstream537eaa2 TLS accept-loop panics/serial handshakes, task admission and pre-allocation line/DATA bounds; add a bounded async streaming DATA callback.
- Maintain one patched SMTP state machine. Use Mailin core behavior/tests as references, retain all required attribution and record source-derived changes. Product policy does not enter this library.
- Read the approved product HNR plan, exact published wire contracts and source review before choosing technical fields; reject unsupported or unconfigured capability.
- Implement library/source changes with bounded native integration tests, retain exact provenance and update progress/evidence without claiming fixture acceptance as live deployment.
- Map Mailin mailin core HELO/MAIL/RCPT/null sender/data_start/data/data_end/RSET tests into this one async runtime; mailin-embedded TLS/lifecycle and mailin-server diagnostics are references only. mxdns maps to GATE-004 bounded DNS; mime-event remains a source-checked measured-gap candidate under engine MIME ownership.

## Data and state

Bounded socket/session/TLS/parser/transaction state and shared immutable configuration only; all product identity, grants, storage and durable receipt state remain with callers.

## Contracts

SMTP protocol boundary only: immutable accepted EHLO capabilities, explicit pre-greeting/MAIL/RCPT/DATA/STARTTLS/RSET/QUIT state, bounded asynchronous DATA sink/finalisation callbacks and typed temporary/permanent responses. Final250 is emitted only after the handler confirms durable acceptance; cancellation/error aborts the transaction. TLS restart clears pre-TLS auth/envelope state. This library owns no product HTTP operation/grant/SQL schema.

## Permissions and isolation

Protocol enforces declared TLS-before-auth/role capabilities and callback ordering; it cannot authorise product users or relay recipients itself. Gateway role handlers must explicitly accept every recipient and finalisation. Never infer trust from EHLO/header/proxy text.

## Resource bounds

Check command/header/DATA line length before allocation, bounded DATA chunk buffers and total bytes, finite recipients, connections and concurrent TLS handshakes, absolute greeting/read/write/transaction deadlines and cooperative drain/cancel. One failed/slow handshake cannot block or panic the accept loop.

## Library source and reuse

Pin ROU-Technology/rou-mail-smtpd source revision; use Tokio/rustls/bytes and official storage SDKs. Mailin core is a behavioral reference, not a second runtime. See product research/mail-stack-source-review-2026-10-24.md. Component-by-component source and tests: product docs/product-plan/advancements/direct-inbound-contract.md#mailin-component-mapping; https://code.alienscience.org/alienscience/mailin and https://docs.rs/mailin/0.6.5/mailin/. Never add the blocking embedded server or duplicate live parser.

## Failure and recovery

- RSET, rejected MAIL/RCPT/DATA, transaction end and STARTTLS reset the exact allowed state; no stale sender/recipient/auth crosses transactions or security boundaries.
- On timeout, disconnect, failed sink or cancellation, stop new chunks and finalisation without success; caller retains durable receipt ambiguity and storage cleanup authority. Library never spools/resends mail.

## Acceptance

- Real TCP/TLS transcript and property/fuzz tests: failed/slow handshake survival, RSET/STARTTLS/DATA state reset, null sender, dot transparency, size limits, capability honesty, backpressure, shutdown and resource headroom.
- Run native Linux process/IPC/TCP/TLS/storage failure tests with normal container security, exact source/runtime digests and explicit skipped/unverified target-host/provider gates.

## Test environments

Use isolated PostgreSQL/native framework checks for product state and actual Linux processes, private object stores, protocol clients and source-authentication fixtures for the service seam. Record every skip and actual runtime limits; fixture/protocol success is not live DNS, native target-host or combined pilot acceptance.

## Reversal

Stop new admission before rollback. Preserve all accepted originals, receipt/store identities, audit and started/unknown outbound attempts. Retire revisions prospectively; never rewrite historical bindings, delete a sole original or introduce an automatic provider/storage fallback.
