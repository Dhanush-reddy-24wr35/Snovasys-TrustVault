# API reference

The API is a set of Postgres functions called with `supabase.rpc(name, args)`. Tables and files cannot be reached
any other way. All of them need a signed-in, **approved and active** account unless stated. Each call re-checks that
from the database. A refusal comes back as `{ ok: false, kind: 'forbidden' | 'invalid', message }`; refusals of
protected actions are written to the audit log as DENIED.

Document access levels: **owner** (uploaded it, role owner) > **edit** (granted, and an owner-role account) > **read**
(granted, or visible to everyone; administrators never get read through "everyone").

## Documents

| Function | Who may call it | What it does | Audit |
|---|---|---|---|
| `list_documents(q, owner, category, from, to)` | any user | Documents the caller can access, filtered by name, owner, category, date | none |
| `inspect_document(id)` | read+ | Metadata, text content (text files), and for the owner the grants and trail | READ (always) |
| `doc_details(id)` | read+ | Same without content, to refresh an open view | refusals only |
| `download_document(id)` | read+ | File as base64 | DOWNLOAD |
| `create_document(name, category, visibility, editors, data)` | role **owner** | Validates and stores a new document (data is base64, max 3 MB) | UPLOAD, or DENIED with the reason |
| `commit_edit(id, name, category, expected, text)` | edit+ | Rename, recategorise, change text. `expected` = version the caller saw | CHANGE |
| `replace_file(id, expected, data)` | edit+ | New version of a PDF/PNG (same type) | CHANGE |
| `remove_document(id)` | owner of the document | Deletes document, grants and file | DELETE |
| `set_visibility(id, 'everyone'\|'private')` | owner of the document | Who can view | VISIBILITY |
| `grant_access(id, user, 'read'\|'edit')` | owner of the document | Grant to a named, approved user. `edit` only to owner-role accounts | PERMISSION_GRANT |
| `revoke_access(id, user)` | owner of the document | Withdraw a grant, effective immediately | PERMISSION_REVOKE |

## Accounts and administration

| Function | Who | What | Audit |
|---|---|---|---|
| `login_check()` | signed-in | Confirms the account may sign in | LOGIN (allowed or DENIED) |
| `logout()`, `me()`, `directory()` | signed-in | Session helpers | LOGOUT |
| `admin_overview()` | admin | Register of documents (names and sharing, never contents), people, last 200 log entries | refusals |
| `admin_log(before, limit, outcome, action)` | admin | Whole audit log, paged and filterable | refusals |
| `verify_log()` | admin | Re-computes the hash chain and compares the end with the anchor | VERIFY |
| `decide(user, approve, owner)` | admin | Approve or reject a registration (viewers need an owner) | APPROVE / REJECT |
| `set_role(user, role)`, `set_active(user, on)`, `assign_owner(viewer, owner)`, `admin_people()` | admin | Account management | ROLE_CHANGE / ACCOUNT / OWNER_ASSIGN |
| `my_team()` | owner | The viewers who belong to the caller | refusals |

## Help desk

| Function | Who | Rule |
|---|---|---|
| `help_create(subject, body, category, priority)` | owner, viewer | A viewer's request goes to their owner; an owner's goes to the administrators; admins cannot raise requests |
| `help_list()` | any user | Only requests the caller is part of (admins see only those addressed to admins) |
| `help_reply(ticket, body)` | participants | The person who raised it cannot reply until the other side has answered |
| `help_status(ticket, 'open'\|'resolved')` | participants | Close or reopen |

## Signed-out callers (the only two)

| Function | What | Limits |
|---|---|---|
| `username_available(username)` | Is this username free? | boolean only |
| `log_failed_login(email, reason)` | Records a failed sign-in as DENIED LOGIN | fixed reasons, max 30 entries/minute, marked *client-reported* |

Anything else called while signed out is refused by the database (no EXECUTE privilege).
