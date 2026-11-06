# Threat model

Assets: document contents, the permission model, the audit trail, accounts. Attackers considered: a signed-in user
(viewer or owner) trying to reach someone else's documents, a curious or compromised administrator, an anonymous
internet user, and a user who tampers with their own browser or calls the API directly.

## Attacks considered and how they are handled

| # | Attack | Mitigation | Proven by |
|---|---|---|---|
| 1 | **Reading, downloading, editing, deleting or sharing another user's document** by calling the API with its id | Every function recomputes access from stored grants (`access_of`); refusals are returned and logged | `tests/db` "bob cannot …" (9 checks), `tests/api` first test |
| 2 | **Skipping the page** (hidden buttons, edited JavaScript, calling `rpc` directly) | No rule lives in the page. The page is a viewer of the API | all tests call functions directly |
| 3 | **Direct table or file access** | RLS on, all privileges revoked for API roles; files live in the database, Storage policies removed | "direct table access refused", `tests/api` no-direct-routes test |
| 4 | **Audit bypass** (a read that is not logged; downloading through another route) | There is one route per action, each logs in the same transaction. The old "quiet" read parameter was removed | "there is no quiet read any more", "reading writes a READ entry" |
| 5 | **Administrator as back door** | Admins have no access to contents: not by "everyone", not by default. They see a register (names, owners, grants) and the log | "admin cannot read contents" |
| 6 | **Privilege escalation** (register as admin, change own role, make self owner of a viewer) | Sign-up trigger only allows owner or viewer, new accounts are unapproved until an admin approves; only admin functions change roles, and they check the caller | schema trigger, `decide`, `set_role` |
| 7 | **Stale access** (revoked user keeps reading; deactivated user keeps a session) | Access is recomputed per call; `private.me()` requires approved AND active on every call; deactivation bans the user and deletes sessions | "revocation is immediate (read/download)" |
| 8 | **Tampering with the audit trail**: edit, delete, truncate, remove the newest entries, rewrite history | Append-only triggers refuse update/delete/truncate; each entry is HMAC-chained with a secret API roles cannot read; an anchor records the newest entry so removing the tail is detected; admin can verify | "audit log refuses …", "chain verifies", "deleting the newest entries is detected" |
| 9 | **Flooding the log** to bury real activity or slow writers | After 100 refusals by one user in a minute a single RATE_LIMIT entry replaces the rest of that minute; allowed actions are never dropped; admin log is paged and filterable | "flood is summarised" |
| 10 | **Malicious uploads**: wrong type behind a good extension, binary in a text file, invalid UTF-8/JSON, path-traversal names, oversize | Server-side `check_content` (PDF/PNG headers, UTF-8, NUL bytes, JSON), name whitelist, extension whitelist, 3 MB cap; rejections are audited | "fake PDF rejected", and the other upload checks |
| 11 | **Stored XSS** through file names or text content | Page builds the DOM with text nodes (no `innerHTML` for user data); text shown in `<pre>` via text nodes; no HTML/SVG uploads; strict Content-Security-Policy | code review, CSP |
| 12 | **Lost update / two editors overwrite each other** | Optimistic version check plus row lock (`for update`) | "stale version is refused" |
| 13 | **SQL injection** | Functions take typed parameters; there is no dynamic SQL; PostgREST passes parameters separately | code review |
| 14 | **Privilege use by signed-out callers** | EXECUTE revoked from anon on everything except two limited helpers | "signed-out caller cannot call list_documents" |
| 15 | **Help desk abuse** (viewer reaching an admin, replying to oneself, reading others' tickets) | Recipient is chosen by the server from the caller's role; participants-only access; requester cannot reply twice in a row | "requester cannot reply …", "another owner cannot join" |
| 16 | **Service-role key exposure** | Only used by `seed.mjs` and tests via `.env` (ignored by Git); the page contains only the public anon key | `.gitignore` |

## Accepted risks (known, and why)

1. **Database administrators are trusted.** Someone with owner/superuser access to Postgres can disable triggers, read
   `private.secrets` and rewrite the log and its anchor. The design makes API users unable to do this and makes casual
   tampering detectable, not an insider with full database control. For stronger guarantees, ship log entries to an
   external append-only store.
2. **Failed sign-ins are client-reported.** Supabase Auth does not call our database, so the page reports them and an
   anonymous caller could forge or flood these entries (limited to 30 a minute, marked "client-reported"). A reliable
   alternative is Auth hooks (paid plans) or Supabase Auth logs.
3. **No custom lockout.** Brute force is limited by Supabase Auth's built-in rate limits only. A lockout we control would
   let anyone lock out any user by calling the unauthenticated logging helper.
4. **User enumeration.** `username_available` and the "deactivated / confirm your email" messages reveal that an account
   exists. Needed for usable sign-up; wrong-password and unknown-email answers are identical.
5. **Supabase script loaded from a CDN without an integrity hash**, so a CDN compromise could run code in the page. The CSP
   limits where it can send data. Fix: self-host the file or pin a version and add `integrity=`.
6. **Files are stored in Postgres as bytea and sent as base64**, so the 3 MB limit is deliberately small. Larger files would
   need object storage with signed, logged URLs.
7. **Download copies are outside our control.** Once a permitted user downloads a file, revoking access cannot recall it.
8. **Text of documents is not encrypted at rest** beyond what Supabase provides.
9. **A stolen access token stays valid until it expires**, but the database refuses every call from a deactivated or
   unapproved account immediately, so the damage window for a removed user is zero.
