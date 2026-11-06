# AI-use log

Tool: Claude (Anthropic) in the Claude app. Entries are dated and say what I asked, what came back, and what was
checked or corrected. **Review and edit the "My check" lines so they are true for you before you submit.** Anything
marked TODO has not been done yet.

---

## 2026-11-06 (morning), bug fixes to the first version
**Asked:** (paraphrased) allow 3 MB uploads instead of 1 MB; the help-desk request chat is cramped and the person who
raised a request can reply to their own request; log failed sign-ins in the activity log; the sign-in form loses what I
typed after a wrong password; every username must be unique.
**Got:** edits to `index.html` plus a first `backend_changes.sql`.
**Caught / corrected:** the first SQL file was written *without seeing my schema*, so it guessed a table name
(`profiles`) and a log function (`write_log`) and told me to adapt them. When I supplied `schema.sql` and
`help_desk.sql` it was rewritten against the real `private.log` and showed that usernames were **already unique** in
the schema (so no extra index was needed, only a pre-check function). Lesson: give the AI the real schema first.
**My check:** TODO (confirm each fix in the running site).

## 2026-11-06, security review against the assessment brief (authorization and auditing)
**Asked:** check the project against the assignment requirements and mark it.
**Got:** a review that found real gaps in the **auditing** design: `inspect_document(p_id, p_quiet)` let the caller skip
the READ entry; Storage policies allowed direct reads/uploads/deletes with no audit entry; upload content checks
(PDF/PNG headers, UTF-8, JSON) existed only in browser code; the log could be truncated without detection and flooded
with refusals.
**Verified:** I read `schema.sql` myself and confirmed the `p_quiet` parameter and the three `storage.objects` policies.
**My check:** TODO (note which findings you reproduced).

## 2026-11-06, hardening migration (authorization and auditing)
**Asked:** fix everything from the review.
**Got:** `sql/03_hardening.sql`: files moved into the database so every file action is a function that checks access and
logs in the same transaction; server-side `check_content`; append-only triggers, an anchor row, flood limit; `verify_log`
extended; row locking on edits; admin log paging.
**Caught / corrected:** nothing recorded yet. TODO: write down anything you found wrong in this migration when you reviewed it
(for example by reading each function against the brief).
**My check:** TODO.

## 2026-11-06, database tests proving one user cannot reach another's documents
**Asked:** automated tests for the authorization and audit requirements.
**Got:** `tests/db/hardening_test.sql` (70 checks) run on a local Postgres 16 with stand-ins for Supabase's `auth` and
`storage` schemas.
**Caught / corrected:** the first runs failed because of mistakes **in the tests**, not the SQL: queries run while
impersonating a user instead of as the superuser, a `RAISE` that printed `t` instead of `true`, a wrong bytea literal,
a variable named `doc` clashing with a column, and an expectation of the original text after another user had edited it.
All 70 then passed. Also found: my scratch database kept crashing because the sandbox reset folder permissions; the data
directory was moved.
**My check:** TODO (run `npm run test:db` yourself and read the output).

## 2026-11-06, API tests, seed accounts, front-end changes
**Asked:** tests through the public API, seed accounts for each role, and the page updated for the new API.
**Got:** `tests/api/authorization.test.mjs`, `scripts/seed.mjs`, changes to `index.html` (no Storage, replace-file for
PDF/PNG, filterable activity log, Content-Security-Policy).
**Limits:** these were only syntax-checked (`node --check`); they have **not** been run against a Supabase project
because the AI had no access to one. TODO: run `npm run seed` and `npm test` on a test project and record the result here.

## 2026-11-06, threat model and documents
**Asked:** THREATS.md, API docs, README, write-up and demo script.
**Got:** the documents in this repository.
**Caught / corrected:** the CDN script has no integrity hash because it could not be fetched from the sandbox to compute one;
this is listed in THREATS.md as an **accepted risk** rather than claimed as fixed.
**My check:** TODO (read THREATS.md and strike anything you cannot defend in a viva).
