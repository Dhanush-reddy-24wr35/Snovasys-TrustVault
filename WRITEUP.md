# TrustVault: short write-up

**Goal.** Let a team share documents with named people, with three roles, and be able to prove afterwards who tried to
do what, including the attempts that were refused.

**Approach.** The browser is untrusted. The database is the only place rules exist. Tables are closed; the API is a set
of Postgres functions that each re-check the caller and the document's grants, then act and log in one transaction.
Refusals are returned (not raised) so their audit entry is kept. The audit log is an HMAC hash chain that cannot be
read by API users, refuses updates and deletes, and is anchored so removing the newest entries is noticed.

**Key decision: files in the database.** The first version kept files in Supabase Storage with policies. Reviewing it
against the brief showed that direct Storage calls, and a client-controlled "quiet" read flag, let a permitted user read
without an audit entry, and that upload checks ran only in the browser. Moving file bytes into Postgres gives one
route per action, so authorization, validation and auditing cannot be bypassed. The cost is a 3 MB limit.

**Verification.** 70 SQL checks run against a real Postgres: cross-user denial for every action, admin has no content
access, revocation is immediate, refusals are logged, validation, append-only log, tail-removal detection, flood
limit. API tests repeat the key checks as signed-in users and verify tables and Storage cannot be reached directly.

**Limits.** See THREATS.md: trusted DB administrators, client-reported failed sign-ins, no custom lockout, CDN script
without integrity hash, 3 MB files. The page is a single file; splitting it and adding browser tests are the next
engineering steps.
