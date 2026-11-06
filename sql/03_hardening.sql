-- =====================================================================
-- TrustVault: hardening migration  (run THIRD, after 01_schema.sql and 02_help_desk.sql)
-- Supabase: SQL Editor -> New query -> paste all -> Run.  Safe to run twice.
--
-- What it changes, and why
--   1. FILES LIVE IN THE DATABASE, not in Storage. Every read, download, edit and
--      delete now goes through a function that checks the caller, checks the
--      document's grants, and writes the audit entry in the SAME transaction.
--      There is no direct file route left to bypass the audit trail.
--      (The old Storage policies are dropped.)
--   2. The server validates every upload itself (size, type, real PDF/PNG header,
--      UTF-8 text, valid JSON). The browser checks are only early feedback.
--   3. Reading a document is ALWAYS audited (the old "quiet" option is gone).
--   4. The audit log is append-only (updates, deletes and truncates are refused)
--      and has an "anchor" so removing the newest entries is detected too.
--      A user who triggers hundreds of refusals a minute cannot bury real
--      activity: after 100 refusals the rest of that minute is summarised.
--   5. Uploads up to 3 MB; an owner can replace PDF/PNG files with a new version.
--   6. Row locking on edits (two people cannot overwrite each other).
--   7. The failed-sign-in log, username check and help-desk reply rule.
--   8. Admins can page and filter the whole activity log.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. File bytes in the database
-- ---------------------------------------------------------------------
create table if not exists public.doc_files (
  doc_id  bigint not null references public.documents(id) on delete cascade,
  version int    not null,
  content bytea  not null,
  primary key (doc_id, version)
);
alter table public.doc_files enable row level security;
revoke all on public.doc_files from anon, authenticated;

-- direct file routes are closed
drop policy if exists "vault read"   on storage.objects;
drop policy if exists "vault upload" on storage.objects;
drop policy if exists "vault delete" on storage.objects;

-- half-finished uploads from the old two-step flow
delete from public.documents where not ready;

-- 3 MB table rule (drop whatever 1 MB rule exists first)
do $$
declare c text;
begin
  for c in select conname from pg_constraint
            where conrelid = 'public.documents'::regclass and contype = 'c'
              and pg_get_constraintdef(oid) like '%1048576%'
  loop execute format('alter table public.documents drop constraint %I', c); end loop;
end $$;
alter table public.documents drop constraint if exists documents_size_3mb;
alter table public.documents add constraint documents_size_3mb check (size between 1 and 3145728);

-- old functions that talked to Storage
drop function if exists public.create_document(text, text, text, uuid[], int);
drop function if exists public.finish_upload(bigint);
drop function if exists public.cancel_upload(bigint);
drop function if exists public.inspect_document(bigint, boolean);
drop function if exists public.commit_edit(bigint, text, text, int, int);

-- ---------------------------------------------------------------------
-- 2. Server-side content checks
-- ---------------------------------------------------------------------
-- returns NULL when the bytes are acceptable for this file type, otherwise the reason
create or replace function private.check_content(p_ext text, p_b bytea) returns text
language plpgsql immutable set search_path = '' as $$
declare t text;
begin
  if p_b is null or length(p_b) < 1 then return 'The file is empty.'; end if;
  if length(p_b) > 3145728 then return 'The file is bigger than 3 MB.'; end if;
  if p_ext = 'pdf' then
    if substring(p_b from 1 for 5) <> '\x255044462d'::bytea then return 'The content is not a real PDF.'; end if;
  elsif p_ext = 'png' then
    if substring(p_b from 1 for 8) <> '\x89504e470d0a1a0a'::bytea then return 'The content is not a real PNG.'; end if;
  elsif p_ext in ('txt', 'md', 'csv', 'json') then
    if position('\x00'::bytea in p_b) > 0 then return 'Binary data found inside a text file.'; end if;
    begin t := convert_from(p_b, 'UTF8');
    exception when others then return 'The text is not valid UTF-8.'; end;
    if p_ext = 'json' then
      begin perform t::jsonb;
      exception when others then return 'This is not valid JSON.'; end;
    end if;
  else
    return 'That file type is not accepted.';
  end if;
  return null;
end $$;

-- shared answer for "open this document": meta, who can edit, grants + trail (owner only)
create or replace function private.doc_payload(d public.documents, a text, u public.profiles) returns jsonb
language plpgsql stable security definer set search_path = '' as $$
declare mine boolean := d.owner_id = u.id and u.role = 'owner';
begin
  return jsonb_build_object(
    'meta', private.meta(d, a),
    'editors', (select jsonb_agg(x) from (
                  select d.owner_id as x
                  union all
                  select g.user_id from public.doc_grants g where g.doc_id = d.id and g.perm = 'edit') s),
    'grants', case when mine then coalesce((select jsonb_agg(jsonb_build_object('user', g.user_id, 'perm', g.perm))
                                            from public.doc_grants g where g.doc_id = d.id), '[]'::jsonb) end,
    'trail',  case when mine then coalesce((select jsonb_agg(to_jsonb(t)) from (
                                  select * from public.audit_log where doc = d.id order by seq desc limit 60) t), '[]'::jsonb) end);
end $$;

revoke execute on function private.check_content(text, bytea), private.doc_payload(public.documents, text, public.profiles) from public;

-- ---------------------------------------------------------------------
-- 3. Audit log: append-only, anchored, flood-limited
-- ---------------------------------------------------------------------
create index if not exists audit_log_actor_ts_idx on public.audit_log(actor, ts desc);

-- the anchor remembers the newest entry, so removing entries from the END is noticed
create table if not exists private.audit_anchor (
  id   int primary key check (id = 1),
  seq  bigint not null,
  hash text   not null
);
insert into private.audit_anchor(id, seq, hash)
select 1, coalesce((select max(seq) from public.audit_log), 0),
          coalesce((select hash from public.audit_log order by seq desc limit 1), repeat('0', 64))
on conflict (id) do nothing;

create or replace function private.audit_after_insert() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  update private.audit_anchor set seq = new.seq, hash = new.hash where id = 1;
  return null;
end $$;
drop trigger if exists audit_anchor_t on public.audit_log;
create trigger audit_anchor_t after insert on public.audit_log
for each row execute function private.audit_after_insert();

create or replace function private.audit_block() returns trigger
language plpgsql set search_path = '' as $$
begin
  raise exception 'The audit log is append-only.' using errcode = '42501';
end $$;
drop trigger if exists audit_no_change   on public.audit_log;
drop trigger if exists audit_no_truncate on public.audit_log;
create trigger audit_no_change   before update or delete on public.audit_log
for each row       execute function private.audit_block();
create trigger audit_no_truncate before truncate on public.audit_log
for each statement execute function private.audit_block();

-- same as schema.sql, plus: after 100 refusals by one person in a minute, write ONE
-- summary entry and skip the rest of that minute (allowed actions are always logged)
create or replace function private.log(p_actor uuid, p_action text, p_doc bigint, p_outcome text, p_detail text)
returns void language plpgsql security definer set search_path = '' as $$
declare an text; dn text; n int;
begin
  select name into an from public.profiles where id = p_actor;
  if p_outcome = 'DENIED' and p_actor is not null then
    select count(*) into n from public.audit_log
     where actor = p_actor and outcome = 'DENIED' and ts > now() - interval '1 minute';
    if n >= 100 then
      if not exists (select 1 from public.audit_log
                      where actor = p_actor and action = 'RATE_LIMIT' and ts > now() - interval '1 minute') then
        insert into public.audit_log(actor, actor_name, action, outcome, detail)
        values (p_actor, an, 'RATE_LIMIT', 'DENIED', 'more than 100 refused attempts in a minute; further refusals are not listed for the next minute');
      end if;
      return;
    end if;
  end if;
  if p_doc is not null then select name into dn from public.documents where id = p_doc; end if;
  insert into public.audit_log(actor, actor_name, action, doc, doc_name, outcome, detail)
  values (p_actor, an, p_action, p_doc, dn, p_outcome, left(coalesce(p_detail, ''), 300));
end $$;

-- verification now also compares the end of the chain with the anchor
create or replace function public.verify_log() returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); r public.audit_log; prev text := repeat('0', 64); last bigint := 0; n bigint := 0; total bigint;
        a_seq bigint; a_hash text;
begin
  if u.id is null then return private.gone(); end if;
  if u.role <> 'admin' then return private.deny(u.id, 'VERIFY', null, 'Administrators only.'); end if;
  perform pg_advisory_xact_lock(727001);                      -- no new entries while we check
  select count(*) into total from public.audit_log;
  for r in select * from public.audit_log order by seq loop
    n := n + 1;
    if r.prev <> prev or r.seq <> last + 1 or private.seal(r, prev) <> r.hash then
      perform private.log(u.id, 'VERIFY', null, 'ALLOWED', 'broken at ' || r.seq);
      return jsonb_build_object('ok', false, 'checked', total, 'brokenAt', r.seq);
    end if;
    prev := r.hash; last := r.seq;
  end loop;
  select seq, hash into a_seq, a_hash from private.audit_anchor where id = 1;
  if a_seq is distinct from last or a_hash is distinct from prev then
    perform private.log(u.id, 'VERIFY', null, 'ALLOWED', 'entries missing after #' || last);
    return jsonb_build_object('ok', false, 'checked', total, 'brokenAt', last + 1, 'truncated', true);
  end if;
  perform private.log(u.id, 'VERIFY', null, 'ALLOWED', 'intact, ' || n || ' entries');
  return jsonb_build_object('ok', true, 'checked', n, 'head', prev);
end $$;

-- administrators: the whole log, newest first, filterable, 100 at a time
create or replace function public.admin_log(
  p_before bigint default null, p_limit int default 100, p_outcome text default null, p_action text default null) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); lim int := least(greatest(coalesce(p_limit, 100), 1), 200); r jsonb; n bigint;
begin
  if u.id is null then return private.gone(); end if;
  if u.role <> 'admin' then return private.deny(u.id, 'ADMIN_VIEW', null, 'Administrators only.'); end if;
  select coalesce(jsonb_agg(to_jsonb(l) order by l.seq desc), '[]'::jsonb), count(*) into r, n
    from (select * from public.audit_log
           where (p_before is null or seq < p_before)
             and (nullif(p_outcome, '') is null or outcome = p_outcome)
             and (nullif(p_action, '')  is null or action = p_action)
           order by seq desc limit lim + 1) l;
  return jsonb_build_object('rows', case when n > lim then r - lim else r end, 'more', n > lim);
end $$;

-- ---------------------------------------------------------------------
-- 4. Documents: every file route is a function that checks AND logs
-- ---------------------------------------------------------------------
-- p_data is the file as base64. Validation happens here, on the server.
create or replace function public.create_document(
  p_name text, p_category text, p_visibility text, p_editors uuid[], p_data text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); ext text; e uuid; t public.profiles; b bytea; msg text; new_id bigint;
begin
  if u.id is null then return private.gone(); end if;
  if u.role <> 'owner' then return private.deny(u.id, 'UPLOAD', null, 'Only document owners can upload.'); end if;
  if p_name is null or p_name !~ '^[A-Za-z0-9_ .()-]{1,100}$' or position('..' in p_name) > 0 or left(p_name, 1) = '.' then
    return private.invalid('File name: 1-100 characters; letters, digits, space, dot, dash, underscore and brackets only.');
  end if;
  ext := case when position('.' in p_name) > 0 then lower(substring(p_name from '[^.]*$')) else '' end;
  if ext not in ('txt','md','csv','json','pdf','png') then
    return private.invalid('.' || ext || ' files are not accepted (allowed: txt, md, csv, json, pdf, png).');
  end if;
  if p_category not in ('Contract','HR','Finance','Engineering','Audit','Other') then return private.invalid('Choose one of the listed categories.'); end if;
  if p_visibility not in ('everyone','private') then return private.invalid('Pick who can view the document.'); end if;
  if p_data is null or length(p_data) > 4300000 then
    perform private.log(u.id, 'UPLOAD', null, 'DENIED', 'rejected: too large or missing (' || left(coalesce(p_name, ''), 60) || ')');
    return private.invalid('The file is empty or bigger than 3 MB.');
  end if;
  begin b := decode(p_data, 'base64'); exception when others then return private.invalid('The file data is not valid.'); end;
  msg := private.check_content(ext, b);
  if msg is not null then
    perform private.log(u.id, 'UPLOAD', null, 'DENIED', 'rejected: ' || msg || ' (' || left(p_name, 60) || ')');
    return private.invalid(msg);
  end if;
  foreach e in array coalesce(p_editors, '{}'::uuid[]) loop
    select * into t from public.profiles where id = e;
    if t.id is null or t.id = u.id or t.role <> 'owner' or not t.approved or not t.active then
      return private.invalid('Editors must be other active document owners.');
    end if;
  end loop;
  insert into public.documents(name, ext, category, owner_id, visibility, size, ready)
  values (p_name, ext, p_category, u.id, p_visibility, length(b), true) returning id into new_id;
  insert into public.doc_files(doc_id, version, content) values (new_id, 1, b);
  insert into public.doc_grants(doc_id, user_id, perm)
  select new_id, x, 'edit' from unnest(coalesce(p_editors, '{}'::uuid[])) x on conflict do nothing;
  perform private.log(u.id, 'UPLOAD', new_id, 'ALLOWED', p_category || ', ' || length(b) || ' bytes, ' || p_visibility);
  return jsonb_build_object('ok', true, 'id', new_id);
end $$;

-- opening a document: ALWAYS logged (there is no quiet option)
create or replace function public.inspect_document(p_id bigint) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); d public.documents; denial jsonb; a text; c bytea; txt text;
begin
  if u.id is null then return private.gone(); end if;
  denial := private.gate(u, p_id, 'READ', 'read');
  if denial is not null then return denial; end if;
  select * into d from public.documents where id = p_id;
  a := private.access_of(d.id, u.id);
  if d.ext in ('txt','md','csv','json') then
    select content into c from public.doc_files where doc_id = d.id and version = d.version;
    if c is null then return private.invalid('This file was stored by an older version of TrustVault. Ask the owner to upload it again.'); end if;
    txt := convert_from(c, 'UTF8');
  end if;
  perform private.log(u.id, 'READ', d.id, 'ALLOWED', '');
  return private.doc_payload(d, a, u) || jsonb_build_object('text', txt);
end $$;

-- details only (no file content): used to keep an open drawer fresh. Refusals are logged.
create or replace function public.doc_details(p_id bigint) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); d public.documents; denial jsonb;
begin
  if u.id is null then return private.gone(); end if;
  denial := private.gate(u, p_id, 'READ', 'read');
  if denial is not null then return denial; end if;
  select * into d from public.documents where id = p_id;
  return private.doc_payload(d, private.access_of(d.id, u.id), u);
end $$;

create or replace function public.download_document(p_id bigint) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); d public.documents; denial jsonb; c bytea;
begin
  if u.id is null then return private.gone(); end if;
  denial := private.gate(u, p_id, 'DOWNLOAD', 'read');
  if denial is not null then return denial; end if;
  select * into d from public.documents where id = p_id;
  select content into c from public.doc_files where doc_id = d.id and version = d.version;
  if c is null then return private.invalid('This file was stored by an older version of TrustVault. Ask the owner to upload it again.'); end if;
  perform private.log(u.id, 'DOWNLOAD', d.id, 'ALLOWED', '');
  return jsonb_build_object('name', d.name, 'ext', d.ext, 'data', replace(encode(c, 'base64'), E'\n', ''));
end $$;

-- rename / recategorise / change text. p_text is the new text (null = text unchanged).
create or replace function public.commit_edit(
  p_id bigint, p_name text, p_category text, p_expected int, p_text text default null) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); d public.documents; denial jsonb; notes text[] := '{}';
        b bytea; c bytea; msg text; new_v int;
begin
  if u.id is null then return private.gone(); end if;
  denial := private.gate(u, p_id, 'CHANGE', 'edit');
  if denial is not null then return denial; end if;
  select * into d from public.documents where id = p_id for update;      -- two edits cannot overlap
  if d.version <> p_expected then
    return private.invalid('This document was changed by someone else. Close it and open it again.');
  end if;
  if p_name is null or p_name !~ '^[A-Za-z0-9_ .()-]{1,100}$' or position('..' in p_name) > 0 or left(p_name, 1) = '.' then
    return private.invalid('File name: 1-100 characters; letters, digits, space, dot, dash, underscore and brackets only.');
  end if;
  if position('.' in p_name) = 0 or lower(substring(p_name from '[^.]*$')) <> d.ext then
    return private.invalid('The name must keep the .' || d.ext || ' ending.');
  end if;
  if p_category not in ('Contract','HR','Finance','Engineering','Audit','Other') then return private.invalid('Choose one of the listed categories.'); end if;
  new_v := d.version;
  if p_text is not null then
    if d.ext not in ('txt','md','csv','json') then return private.invalid('This file type is replaced with a new file, not edited as text.'); end if;
    b := convert_to(p_text, 'UTF8');
    msg := private.check_content(d.ext, b);
    if msg is not null then
      perform private.log(u.id, 'CHANGE', d.id, 'DENIED', 'rejected: ' || msg);
      return private.invalid(msg);
    end if;
    select content into c from public.doc_files where doc_id = d.id and version = d.version;
    if c is distinct from b then
      new_v := d.version + 1;
      insert into public.doc_files(doc_id, version, content) values (d.id, new_v, b);
      delete from public.doc_files where doc_id = d.id and version = d.version;
      notes := array_append(notes, 'text changed');
    end if;
  end if;
  if p_name <> d.name then notes := array_append(notes, 'renamed from ' || d.name); end if;
  if p_category <> d.category then notes := array_append(notes, 'category ' || d.category || ' -> ' || p_category); end if;
  if cardinality(notes) = 0 then return jsonb_build_object('ok', true, 'changed', false, 'version', d.version); end if;
  update public.documents
     set name = p_name, category = p_category, modified_at = now(), version = new_v, size = coalesce(length(b), size)
   where id = d.id;
  perform private.log(u.id, 'CHANGE', d.id, 'ALLOWED', array_to_string(notes, '; ') || ' (v' || new_v || ')');
  return jsonb_build_object('ok', true, 'changed', true, 'version', new_v);
end $$;

-- a new version of a PDF or PNG (same file type)
create or replace function public.replace_file(p_id bigint, p_expected int, p_data text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); d public.documents; denial jsonb; b bytea; msg text; new_v int;
begin
  if u.id is null then return private.gone(); end if;
  denial := private.gate(u, p_id, 'CHANGE', 'edit');
  if denial is not null then return denial; end if;
  select * into d from public.documents where id = p_id for update;
  if d.version <> p_expected then
    return private.invalid('This document was changed by someone else. Close it and open it again.');
  end if;
  if p_data is null or length(p_data) > 4300000 then
    perform private.log(u.id, 'CHANGE', d.id, 'DENIED', 'rejected: too large or missing');
    return private.invalid('The file is empty or bigger than 3 MB.');
  end if;
  begin b := decode(p_data, 'base64'); exception when others then return private.invalid('The file data is not valid.'); end;
  msg := private.check_content(d.ext, b);
  if msg is not null then
    perform private.log(u.id, 'CHANGE', d.id, 'DENIED', 'rejected: ' || msg);
    return private.invalid(msg);
  end if;
  new_v := d.version + 1;
  insert into public.doc_files(doc_id, version, content) values (d.id, new_v, b);
  delete from public.doc_files where doc_id = d.id and version = d.version;
  update public.documents set version = new_v, size = length(b), modified_at = now() where id = d.id;
  perform private.log(u.id, 'CHANGE', d.id, 'ALLOWED', 'file replaced (v' || new_v || ', ' || length(b) || ' bytes)');
  return jsonb_build_object('ok', true, 'version', new_v);
end $$;

create or replace function public.remove_document(p_id bigint) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); d public.documents; denial jsonb;
begin
  if u.id is null then return private.gone(); end if;
  denial := private.gate(u, p_id, 'DELETE', 'owner');
  if denial is not null then return denial; end if;
  select * into d from public.documents where id = p_id;
  perform private.log(u.id, 'DELETE', d.id, 'ALLOWED', '');
  delete from public.documents where id = d.id;               -- grants and file versions go with it
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------------
-- 5. Sign-up and sign-in helpers (callable while signed out, so they are limited)
-- ---------------------------------------------------------------------
create or replace function public.username_available(p_username text) returns boolean
language sql stable security definer set search_path = '' as $$
  select not exists (select 1 from public.profiles where username = lower(btrim(coalesce(p_username, '')))) $$;

-- The page reports a failed sign-in here. It is CLIENT-REPORTED (Supabase Auth itself does
-- not call the database), so the entry says so. Fixed reasons only, and at most 30 entries a minute.
create or replace function public.log_failed_login(p_email text, p_reason text default 'wrong email or password')
returns void language plpgsql security definer set search_path = '' as $$
declare em text := lower(btrim(left(coalesce(p_email, ''), 120))); pid uuid; recent int; why text;
begin
  why := case when p_reason in ('wrong email or password','account deactivated','email not confirmed','rate limited')
              then p_reason else 'wrong email or password' end;
  select count(*) into recent from public.audit_log
   where action = 'LOGIN' and outcome = 'DENIED' and detail like 'failed sign-in%' and ts > now() - interval '1 minute';
  if recent >= 30 then return; end if;
  select id into pid from public.profiles where lower(email) = em;
  perform private.log(pid, 'LOGIN', null, 'DENIED', 'failed sign-in for ' || em || ' (' || why || ', client-reported)');
end $$;

-- ---------------------------------------------------------------------
-- 6. Help desk: the person who raised a request cannot answer their own message
-- ---------------------------------------------------------------------
create or replace function public.help_reply(p_ticket bigint, p_body text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); t public.help_tickets; last_author uuid;
begin
  if u.id is null then return private.gone(); end if;
  select * into t from public.help_tickets where id = p_ticket;
  if t.id is null or not private.help_can(t, u) then
    return private.deny(u.id, 'HELP_REPLY', null, 'request ' || coalesce(p_ticket::text, 'null') || ' is not yours', 'That request is not available to you.');
  end if;
  if char_length(btrim(coalesce(p_body, ''))) not between 1 and 2000 then return private.invalid('Write a reply (up to 2000 characters).'); end if;
  if t.status = 'resolved' then return private.invalid('This request is resolved. Reopen it to reply.'); end if;
  select author_id into last_author from public.help_messages where ticket_id = t.id order by id desc limit 1;
  if t.from_id = u.id and last_author = u.id then
    return private.deny(u.id, 'HELP_REPLY', null, 'replied to own request #' || t.id, 'Please wait for a reply before adding more.');
  end if;
  insert into public.help_messages(ticket_id, author_id, body) values (t.id, u.id, btrim(p_body));
  update public.help_tickets
     set status = case when t.from_id = u.id then 'open' else 'answered' end, updated_at = now()
   where id = t.id;
  perform private.log(u.id, 'HELP_REPLY', null, 'ALLOWED', 'request #' || t.id);
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------------
-- 7. Privileges
-- ---------------------------------------------------------------------
revoke execute on function
  public.create_document(text, text, text, uuid[], text), public.inspect_document(bigint), public.doc_details(bigint),
  public.commit_edit(bigint, text, text, int, text), public.replace_file(bigint, int, text), public.admin_log(bigint, int, text, text),
  public.username_available(text), public.log_failed_login(text, text)
  from public, anon;
grant execute on function
  public.create_document(text, text, text, uuid[], text), public.inspect_document(bigint), public.doc_details(bigint),
  public.commit_edit(bigint, text, text, int, text), public.replace_file(bigint, int, text), public.admin_log(bigint, int, text, text)
  to authenticated;
-- these two have to work before anybody is signed in
grant execute on function public.username_available(text), public.log_failed_login(text, text) to anon, authenticated;
