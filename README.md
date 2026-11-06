# TrustVault

Secure document sharing for a team, with three roles (administrator, owner, viewer), per-document read/edit
permissions, and an audit trail that records every access attempt, allowed or refused.

**Live app:** _paste your deployed URL here_  ·  **Demo video:** _paste the link here_

| Role | Seed account (password `TrustVault#2026`) |
|---|---|
| Administrator | `admin@trustvault.test` |
| Owner | `owner1@trustvault.test`, `owner2@trustvault.test` |
| Viewer | `viewer1@trustvault.test` (belongs to owner1), `viewer2@trustvault.test` (belongs to owner2) |

These are demo accounts created by `npm run seed`. Change or delete them before real use.

## How it is built

```
Browser (index.html, static)  ──supabase-js──▶  Supabase
                                                 ├─ Auth            (sign-in, sessions)
                                                 └─ Postgres        (all rules live here)
                                                      ├─ tables: locked, no direct access (RLS on, no grants)
                                                      ├─ SECURITY DEFINER functions = the API (called with rpc)
                                                      ├─ file bytes (doc_files) stored in the database
                                                      └─ audit_log: HMAC hash chain, append-only, anchored
```

* **Authorization is server-side on every call.** Each function re-reads the caller's account (approved, active, role)
  and the document's grants from stored data. The page only draws results; hiding a button is never the barrier.
* **There is no direct file route.** Files are stored in the database and reachable only through functions that check
  access and write the audit entry in the same transaction. Direct table access is refused for every API role.
* **Every attempt is audited, including refusals.** Functions *return* a refusal instead of raising, so the DENIED entry
  is committed. Entries are chained with an HMAC whose secret API roles cannot read; the log refuses updates, deletes
  and truncation, and an anchor detects removal of the newest entries. Admins can verify the chain and page/filter it.
* **Revocation is immediate**, because access is recomputed from the grants table on each call.
* **Uploads are validated by the server:** name, allowed types (txt, md, csv, json, pdf, png), 3 MB limit,
  real PDF/PNG headers, valid UTF-8 text, valid JSON. Rejections are audited.

## Setup (about 10 minutes)

1. **Create a Supabase project** (free tier is fine). Use a separate project for running the tests.
2. **Auth settings** (Authentication → Providers → Email): set *minimum password length* to 8 or more and, if you
   want sign-ups to work without a mail server, turn off *Confirm email* (the page already makes new accounts wait
   for administrator approval). Password strength is also checked in the page, but only this setting is enforced
   on the server.
3. **Run the SQL once, in this order** (SQL Editor → New query → paste → Run):
   1. `sql/01_schema.sql`
   2. `sql/02_help_desk.sql`
   3. `sql/03_hardening.sql`
4. **Point the page at your project.** In `index.html` set `SUPABASE_URL` and `SUPABASE_ANON_KEY`
   (Project Settings → API → *anon public*; it is designed to be public). The same URL is listed in the page's
   `Content-Security-Policy` `connect-src`; change it there too.
5. **Create the demo accounts.** `cp .env.example .env`, fill in the three values (the **service-role** key stays in `.env`,
   never in the page or Git), then:
   ```bash
   npm install
   npm run seed
   ```
   To make your own first administrator instead: sign up in the page, then run
   `update public.profiles set role = 'admin', approved = true where username = 'your-username';`
6. **Deploy the page.** It is one static file. Any static host works: drag the folder onto Netlify Drop,
   or push to GitHub and enable Pages, or `vercel --prod`. No build step.

> Upgrading from the earlier version that stored files in Supabase Storage? After step 3 old files cannot be
> opened (the bytes are not copied); ask the owners to upload them again. You can empty the `vault` bucket afterwards.

## Tests

```bash
npm run test:db     # 70 checks against a throw-away local Postgres (needs psql, createdb; no Supabase needed)
npm test            # API tests as real users against a Supabase TEST project (uses .env)
```

* `tests/db/` proves, in plain SQL, that one user cannot read, download, edit, replace, delete, share or revoke another
  user's document; that an admin cannot read contents; that revocation takes effect immediately; that refusals are logged;
  that uploads are validated; that the audit log is append-only and truncation is detected; that flooding is bounded.
* `tests/api/` repeats the important ones through the public API as signed-in users, and also checks that tables and
  Storage cannot be reached directly and that signed-out callers are refused.

## Documents

* [API.md](API.md): every endpoint, who may call it, what it audits
* [THREATS.md](THREATS.md): attacks considered, mitigations, accepted risks
* [PROMPTS.md](PROMPTS.md): AI-use log
* [WRITEUP.md](WRITEUP.md): short write-up · [DEMO.md](DEMO.md): demo script

## Files

```
index.html               the whole front end (static)
sql/01_schema.sql        tables, audit chain, core functions
sql/02_help_desk.sql     owner teams and help desk
sql/03_hardening.sql     audited file access, validation, append-only log, 3 MB, fixes
scripts/seed.mjs         demo accounts + sample documents
tests/db/                SQL tests + local runner     tests/api/   API tests
```
