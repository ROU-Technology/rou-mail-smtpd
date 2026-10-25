# Decisions

24 October 2026: owner approved hosted nested reselling advancement and separate source repositories. No self-hosted reseller deployment or pricing redesign. No local mail spool fallback. Retain product authority, immutable store/attempt identities and all third-party notices.

24 October admission decision: bound per-IP and TLS-handshake concurrency below
the global connection budget and derive reverse-DNS work from the session
deadline. Refusals are written to the client while an individual RCPT or
transient non-transport DATA error must not destroy an otherwise usable
session; transport timeout/IO errors still close it. XCLIENT is denied unless
explicitly configured and trusted, and only before a transaction starts.
