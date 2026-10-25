# Linux acceptance

All runtime checks remain open. Test native process memory/CPU/deadline/cancel/shutdown and TCP/TLS/IPC or private-object paths relevant to each contract. Use non-root, capability-drop and no-new-privileges Docker integration when useful; never substitute it for public port25/DNS/TLS, target architecture or sustained host acceptance. No production image build/deployment without operator ownership.


24 October runtime checkpoint: tests/streaming.rs exercises real local TCP/TLS
with finite limits and in-memory generated certificates. Run the locked rustls
and no-default-feature test commands from README. macOS results are37/35
respectively, all passing. Linux CI repeats them; macOS is not Linux evidence.
Still required: native-TLS backend, malicious/property/fuzz corpus, saturation
RSS/CPU measurements under native target-host limits, task/process kill during
ambiguous durable acceptance, public port25/DNS/TLS and actual gateway selected
store/scanner/product/engine/restore pilot. Synthetic sink tests cannot close
those release gates. Async cleanup is not guaranteed on task/process death;
product receipt/grant expiry and reference-checked orphan recovery are mandatory.

24 October admission checkpoint: repeat both locked suites after the per-IP
admission and XCLIENT/RCPT/DATA/STARTTLS continuity changes (macOS45/43 total,
all passing). Add Linux-specific evidence for per-IP saturation and fairness,
reverse-DNS deadline under a hostile resolver, repeated STARTTLS and RCPT
refusal under load, and process/task kill during DATA. Docker remains non-root,
non-privileged and synthetic; it does not replace public port25/DNS/TLS,
native-TLS or sustained host measurements.
