# SMTPD-001: Harden the pinned async SMTP protocol library for the hosted gateway

Status: **planned**. Phase: **HNR**. Product advancement: HNR-05.

Implementation acceptance remains unproven.

## Flows

- Patch upstream537eaa2 TLS accept-loop panics/serial handshakes, task admission and pre-allocation line/DATA bounds; add a bounded async streaming DATA callback.
- Maintain one patched SMTP state machine. Use Mailin core behavior/tests as references, retain all required attribution and record source-derived changes. Product policy does not enter this library.
- Read the approved product HNR plan, exact published wire contracts and source review before choosing technical fields; reject unsupported or unconfigured capability.
- Implement library/source changes with bounded native integration tests, retain exact provenance and update progress/evidence without claiming fixture acceptance as live deployment.

## Data and state

Versioned immutable source/configuration, technical admission/profile references and bounded transient process state only. No product SQL, customer secret database or pricing state belongs in this service.

## Contracts

Maintain one patched SMTP state machine. Use Mailin core behavior/tests as references, retain all required attribution and record source-derived changes. Product policy does not enter this library. Validate exact echoed operation/request identity and unknown fields; finite body/response schemas are published before product consumer enablement.

## Permissions and isolation

Infrastructure principal authorises narrow product calls; customer sessions/keys never grant arbitrary private-object access. Reseller identity and resource policy remain product-owned and rechecked at execution.

## Resource bounds

Required finite positive connection, message/line/response bytes, concurrency, DNS/TLS/read/write/whole-operation deadlines and memory/CPU ceilings. Refuse missing/contradictory budgets at startup; never allocate an unbounded line before checking size.

## Library source and reuse

Pin ROU-Technology/rou-mail-smtpd source revision; use Tokio/rustls/bytes and official storage SDKs. Mailin core is a behavioral reference, not a second runtime. See product research/mail-stack-source-review-2026-10-24.md.

## Failure and recovery

- Lost acceptance/reply remains unknown until the original durable identity reconciles; no automatic replay of an external send or fallback provider/store.
- Crash, cancellation, timeouts and exhausted limits release process capacity safely but never delete an accepted original or reinterpret historical identities.

## Acceptance

- Real TCP/TLS transcript and property/fuzz tests: failed/slow handshake survival, RSET/STARTTLS/DATA state reset, null sender, dot transparency, size limits, capability honesty, backpressure, shutdown and resource headroom.
- Run native Linux process/IPC/TCP/TLS/storage failure tests with normal container security, exact source/runtime digests and explicit skipped/unverified target-host/provider gates.

## Test environments

Use isolated PostgreSQL/native framework checks for product state and actual Linux processes, private object stores, protocol clients and source-authentication fixtures for the service seam. Record every skip and actual runtime limits; fixture/protocol success is not live DNS, native target-host or combined pilot acceptance.

## Reversal

Stop new admission before rollback. Preserve all accepted originals, receipt/store identities, audit and started/unknown outbound attempts. Retire revisions prospectively; never rewrite historical bindings, delete a sole original or introduce an automatic provider/storage fallback.
