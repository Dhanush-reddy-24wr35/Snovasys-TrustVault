-- =====================================================================
-- TrustVault: Supabase schema
-- Run ONCE on a fresh Supabase project (SQL Editor -> New query -> Run).
--
-- Design:
--   * Tables are locked: RLS is on and the API roles have no direct table access.
--   * Every action goes through a SECURITY DEFINER function in the public schema
--     (called as supabase.rpc(...)). Each one re-checks the caller's account,
--     role and the document's grants from stored data, exactly like the old
--     browser-only Vault service did.
--   * Denied attempts are written to the audit log (functions RETURN a refusal
--     instead of raising, so the log entry is not rolled back).
--   * The audit log is a hash chain sealed with a secret that API roles cannot read.
--   * File bytes live in a private Storage bucket "vault"; storage policies reuse
--     the same access rules.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;
grant usage on schema private to authenticated;   -- needed by storage policies only

-- ---------------------------------------------------------------------
-- Tables
-- ---------------------------------------------------------------------
create table public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  name       text not null check (char_length(name) between 2 and 60),
  username   text not null unique check (username ~ '^[a-z0-9_.-]{3,30}$'),
  email      text not null,
  role       text not null default 'viewer' check (role in ('admin','owner','viewer')),
  approved   boolean not null default false,
  active     boolean not null default true,
  created_at timestamptz not null default now()
);
create unique index profiles_email_key on public.profiles (lower(email));

create table public.documents (
  id          bigint generated always as identity primary key,
  name        text not null,
  ext         text not null,
  category    text not null check (category in ('Contract','HR','Finance','Engineering','Audit','Other')),
  owner_id    uuid not null references public.profiles(id),
  visibility  text not null check (visibility in ('everyone','private')),
  created_at  timestamptz not null default now(),
  modified_at timestamptz,
  version     int not null default 1,
  size        int not null check (size between 1 and 1048576),
  ready       boolean not null default false      -- false until the file has arrived in Storage
);
create index documents_owner_idx on public.documents(owner_id);

create table public.doc_grants (
  doc_id  bigint not null references public.documents(id) on delete cascade,
  user_id uuid   not null references public.profiles(id)  on delete cascade,
  perm    text   not null check (perm in ('read','edit')),
  primary key (doc_id, user_id)
);
create index doc_grants_user_idx on public.doc_grants(user_id);

create table public.audit_log (
  seq        bigint primary key,
  ts         timestamptz not null default now(),
  actor      uuid,
  actor_name text,
  action     text not null,
  doc        bigint,
  doc_name   text,
  outcome    text not null default 'ALLOWED' check (outcome in ('ALLOWED','DENIED')),
  detail     text not null default '',
  prev       text not null,
  hash       text not null
);
create index audit_log_doc_idx on public.audit_log(doc);

create table private.secrets (k text primary key, v text not null);
insert into private.secrets values ('audit', encode(extensions.gen_random_bytes(32), 'hex'));

alter table public.profiles   enable row level security;
alter table public.documents  enable row level security;
alter table public.doc_grants enable row level security;
alter table public.audit_log  enable row level security;
-- no policies on purpose: nobody reads or writes these tables directly
revoke all on public.profiles, public.documents, public.doc_grants, public.audit_log from anon, authenticated;

-- ---------------------------------------------------------------------
-- Tamper-evident audit log
-- ---------------------------------------------------------------------
create or replace function private.seal(e public.audit_log, p_prev text)
returns text language sql stable security definer set search_path = '' as $$
  select encode(extensions.hmac(
    jsonb_build_array(p_prev, e.seq,
      to_char(e.ts at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.US'),
      e.actor, e.actor_name, e.action, e.doc, e.doc_name, e.outcome, e.detail)::text,
    (select v from private.secrets where k = 'audit'), 'sha256'), 'hex')
$$;

create or replace function private.audit_before_insert()
returns trigger language plpgsql security definer set search_path = '' as $$
declare last_rec public.audit_log;
begin
  perform pg_advisory_xact_lock(727001);                      -- one writer at a time keeps the chain linear
  select * into last_rec from public.audit_log order by seq desc limit 1;
  new.seq  := coalesce(last_rec.seq, 0) + 1;
  new.prev := coalesce(last_rec.hash, repeat('0', 64));
  new.hash := private.seal(new, new.prev);
  return new;
end $$;

create trigger audit_seal before insert on public.audit_log
for each row execute function private.audit_before_insert();

create or replace function private.log(p_actor uuid, p_action text, p_doc bigint, p_outcome text, p_detail text)
returns void language plpgsql security definer set search_path = '' as $$
declare an text; dn text;
begin
  select name into an from public.profiles where id = p_actor;
  if p_doc is not null then select name into dn from public.documents where id = p_doc; end if;
  insert into public.audit_log(actor, actor_name, action, doc, doc_name, outcome, detail)
  values (p_actor, an, p_action, p_doc, dn, p_outcome, left(coalesce(p_detail, ''), 300));
end $$;

-- ---------------------------------------------------------------------
-- Small helpers
-- ---------------------------------------------------------------------
create or replace function private.rank(a text) returns int
language sql immutable set search_path = '' as $$
  select case a when 'read' then 1 when 'edit' then 2 when 'owner' then 3 else 0 end $$;

create or replace function private.deny(p_actor uuid, p_action text, p_doc bigint, p_detail text, p_msg text default null)
returns jsonb language plpgsql security definer set search_path = '' as $$
begin
  perform private.log(p_actor, p_action, p_doc, 'DENIED', p_detail);
  return jsonb_build_object('ok', false, 'kind', 'forbidden', 'message', coalesce(p_msg, p_detail));
end $$;

create or replace function private.invalid(p_msg text) returns jsonb
language sql immutable set search_path = '' as $$
  select jsonb_build_object('ok', false, 'kind', 'invalid', 'message', p_msg) $$;

create or replace function private.gone() returns jsonb
language sql immutable set search_path = '' as $$
  select jsonb_build_object('ok', false, 'kind', 'forbidden', 'message', 'Your session has ended. Please sign in again.') $$;

-- the signed-in user, but only while approved AND active (checked on every call)
create or replace function private.me() returns public.profiles
language sql stable security definer set search_path = '' as $$
  select p from public.profiles p where p.id = auth.uid() and p.approved and p.active $$;

create or replace function private.brief(u public.profiles) returns jsonb
language sql immutable set search_path = '' as $$
  select jsonb_build_object('id', u.id, 'name', u.name, 'username', u.username, 'role', u.role, 'approved', u.approved, 'active', u.active) $$;

-- access rules (same as the old accessOf)
create or replace function private.access_of(p_doc bigint, p_uid uuid) returns text
language plpgsql stable security definer set search_path = '' as $$
declare u public.profiles; d public.documents; g text;
begin
  select * into u from public.profiles where id = p_uid and approved and active;
  if u.id is null then return null; end if;
  select * into d from public.documents where id = p_doc;
  if d.id is null or not d.ready then return null; end if;
  if d.owner_id = u.id then return case when u.role = 'owner' then 'owner' else 'read' end; end if;
  select perm into g from public.doc_grants where doc_id = d.id and user_id = u.id;
  if g = 'edit' and u.role = 'owner' then return 'edit'; end if;
  if g is not null then return 'read'; end if;
  if d.visibility = 'everyone' and u.role <> 'admin' then return 'read'; end if;
  return null;
end $$;

create or replace function private.my_access(p_doc bigint) returns text
language sql stable security definer set search_path = '' as $$
  select private.access_of(p_doc, auth.uid()) $$;

create or replace function private.doc_exists(p_doc bigint) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.documents where id = p_doc) $$;

-- may the caller write file bytes for this document? (owner/editor, or owner of a pending upload)
create or replace function private.can_write(p_doc bigint) returns boolean
language plpgsql stable security definer set search_path = '' as $$
declare u public.profiles := private.me(); d public.documents;
begin
  if u.id is null or p_doc is null then return false; end if;
  select * into d from public.documents where id = p_doc;
  if d.id is null then return false; end if;
  if not d.ready then return d.owner_id = u.id and u.role = 'owner'; end if;
  return private.access_of(d.id, u.id) in ('owner', 'edit');
end $$;

-- storage object names look like "<docId>/v<version>"
create or replace function private.doc_of(p_name text) returns bigint
language sql immutable set search_path = '' as $$
  select case when p_name ~ '^[0-9]{1,15}/v[0-9]{1,6}$' then split_part(p_name, '/', 1)::bigint end $$;

create or replace function private.meta(d public.documents, a text) returns jsonb
language sql immutable set search_path = '' as $$
  select jsonb_build_object('id', d.id, 'name', d.name, 'ext', d.ext, 'category', d.category, 'owner', d.owner_id,
    'visibility', d.visibility, 'created', d.created_at, 'modified', d.modified_at, 'version', d.version, 'size', d.size, 'access', a) $$;

-- returns NULL when allowed, or a refusal (already logged) when not
create or replace function private.gate(u public.profiles, p_id bigint, p_action text, p_need text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare a text; d public.documents;
begin
  select * into d from public.documents where id = p_id;
  if d.id is null then
    return private.deny(u.id, p_action, null, 'unknown document ' || coalesce(p_id::text, 'null'), 'That document is not available to you.');
  end if;
  a := private.access_of(d.id, u.id);
  if a is null or private.rank(a) < private.rank(p_need) then
    return private.deny(u.id, p_action, d.id,
      case when p_need = 'read' then 'You have no access to this document.'
           else 'This needs ' || p_need || ' access; yours is ' || coalesce(a, 'none') || '.' end);
  end if;
  return null;
end $$;

-- ---------------------------------------------------------------------
-- New sign-ups: create an UNAPPROVED profile (role limited to owner/viewer)
-- ---------------------------------------------------------------------
create or replace function private.handle_new_user() returns trigger
language plpgsql security definer set search_path = '' as $$
declare r text := coalesce(new.raw_user_meta_data->>'role', 'viewer');
begin
  if r not in ('owner', 'viewer') then r := 'viewer'; end if;
  insert into public.profiles(id, name, username, email, role)
  values (new.id,
          btrim(coalesce(new.raw_user_meta_data->>'name', '')),
          lower(btrim(coalesce(new.raw_user_meta_data->>'username', ''))),
          new.email, r);
  perform private.log(new.id, 'REGISTER', null, 'ALLOWED', 'requested role ' || r);
  return new;
end $$;

create trigger on_auth_user_created after insert on auth.users
for each row execute function private.handle_new_user();

-- ---------------------------------------------------------------------
-- Public API (called with supabase.rpc). Success returns the payload;
-- failure returns {ok:false, kind:'forbidden'|'invalid', message}.
-- ---------------------------------------------------------------------
create or replace function public.login_check() returns jsonb
language plpgsql security definer set search_path = '' as $$
declare p public.profiles;
begin
  select * into p from public.profiles where id = auth.uid();
  if p.id is null then return private.deny(null, 'LOGIN', null, 'no profile for this account', 'Invalid credentials'); end if;
  if not p.approved then return private.deny(p.id, 'LOGIN', null, 'not yet approved', 'Your registration is waiting for an administrator to approve it.'); end if;
  if not p.active then return private.deny(p.id, 'LOGIN', null, 'account deactivated', 'This account has been deactivated.'); end if;
  perform private.log(p.id, 'LOGIN', null, 'ALLOWED', '');
  return private.brief(p);
end $$;

create or replace function public.logout() returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me();
begin
  if u.id is not null then perform private.log(u.id, 'LOGOUT', null, 'ALLOWED', ''); end if;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.me() returns jsonb
language plpgsql stable security definer set search_path = '' as $$
declare u public.profiles := private.me();
begin
  if u.id is null then return private.gone(); end if;
  return private.brief(u);
end $$;

create or replace function public.directory() returns jsonb
language plpgsql stable security definer set search_path = '' as $$
declare u public.profiles := private.me();
begin
  if u.id is null then return private.gone(); end if;
  return coalesce((select jsonb_agg(private.brief(p) order by p.created_at) from public.profiles p
                   where u.role = 'admin' or p.approved), '[]'::jsonb);
end $$;

create or replace function public.list_documents(
  p_q text default null, p_owner uuid default null, p_category text default null,
  p_from date default null, p_to date default null) returns jsonb
language plpgsql stable security definer set search_path = '' as $$
declare u public.profiles := private.me();
begin
  if u.id is null then return private.gone(); end if;
  return coalesce((
    select jsonb_agg(private.meta(d, a.access) order by d.id desc)
    from public.documents d
    cross join lateral (select private.access_of(d.id, u.id) as access) a
    where a.access is not null
      and (nullif(btrim(p_q), '') is null or position(lower(btrim(p_q)) in lower(d.name)) > 0)
      and (p_owner is null or d.owner_id = p_owner)
      and (nullif(p_category, '') is null or d.category = p_category)
      and (p_from is null or (d.created_at at time zone 'utc')::date >= p_from)
      and (p_to   is null or (d.created_at at time zone 'utc')::date <= p_to)
  ), '[]'::jsonb);
end $$;

create or replace function public.inspect_document(p_id bigint, p_quiet boolean default false) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); d public.documents; denial jsonb; a text; mine boolean;
begin
  if u.id is null then return private.gone(); end if;
  denial := private.gate(u, p_id, 'READ', 'read');
  if denial is not null then return denial; end if;
  select * into d from public.documents where id = p_id;
  a := private.access_of(d.id, u.id);
  if not coalesce(p_quiet, false) then perform private.log(u.id, 'READ', d.id, 'ALLOWED', ''); end if;
  mine := d.owner_id = u.id and u.role = 'owner';
  return jsonb_build_object(
    'meta', private.meta(d, a),
    'path', d.id || '/v' || d.version,
    'editors', (select jsonb_agg(x) from (
                  select d.owner_id as x
                  union all
                  select g.user_id from public.doc_grants g where g.doc_id = d.id and g.perm = 'edit') s),
    'grants', case when mine then coalesce((select jsonb_agg(jsonb_build_object('user', g.user_id, 'perm', g.perm))
                                            from public.doc_grants g where g.doc_id = d.id), '[]'::jsonb) end,
    'trail',  case when mine then coalesce((select jsonb_agg(to_jsonb(t)) from (
                                  select * from public.audit_log where doc = d.id order by seq desc limit 60) t), '[]'::jsonb) end);
end $$;

create or replace function public.download_document(p_id bigint) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); d public.documents; denial jsonb;
begin
  if u.id is null then return private.gone(); end if;
  denial := private.gate(u, p_id, 'DOWNLOAD', 'read');
  if denial is not null then return denial; end if;
  select * into d from public.documents where id = p_id;
  perform private.log(u.id, 'DOWNLOAD', d.id, 'ALLOWED', '');
  return jsonb_build_object('name', d.name, 'ext', d.ext, 'path', d.id || '/v' || d.version);
end $$;

-- Upload is 3 steps: create_document -> client uploads bytes to Storage -> finish_upload
create or replace function public.create_document(
  p_name text, p_category text, p_visibility text, p_editors uuid[], p_size int) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); ext text; e uuid; t public.profiles; new_id bigint;
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
  if p_size is null or p_size < 1 then return private.invalid('The file is empty.'); end if;
  if p_size > 1048576 then return private.invalid('The file is bigger than 1 MB.'); end if;
  foreach e in array coalesce(p_editors, '{}'::uuid[]) loop
    select * into t from public.profiles where id = e;
    if t.id is null or t.id = u.id or t.role <> 'owner' or not t.approved or not t.active then
      return private.invalid('Editors must be other active document owners.');
    end if;
  end loop;
  insert into public.documents(name, ext, category, owner_id, visibility, size)
  values (p_name, ext, p_category, u.id, p_visibility, p_size) returning id into new_id;
  insert into public.doc_grants(doc_id, user_id, perm)
  select new_id, x, 'edit' from unnest(coalesce(p_editors, '{}'::uuid[])) x on conflict do nothing;
  return jsonb_build_object('id', new_id, 'path', new_id || '/v1');
end $$;

create or replace function public.finish_upload(p_id bigint) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); d public.documents; o storage.objects; sz int;
begin
  if u.id is null then return private.gone(); end if;
  select * into d from public.documents where id = p_id;
  if d.id is null or d.owner_id <> u.id or d.ready then
    return private.deny(u.id, 'UPLOAD', null, 'upload not allowed', 'That upload cannot be completed.');
  end if;
  select * into o from storage.objects where bucket_id = 'vault' and name = d.id || '/v1';
  if o.id is null then return private.invalid('The file did not arrive. Please try again.'); end if;
  sz := coalesce((o.metadata->>'size')::int, d.size);
  update public.documents set ready = true, size = greatest(sz, 1) where id = d.id;
  perform private.log(u.id, 'UPLOAD', d.id, 'ALLOWED', d.category || ', ' || sz || ' bytes, ' || d.visibility);
  return jsonb_build_object('ok', true, 'id', d.id);
end $$;

create or replace function public.cancel_upload(p_id bigint) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me();
begin
  if u.id is null then return private.gone(); end if;
  delete from public.documents where id = p_id and owner_id = u.id and not ready;
  return jsonb_build_object('ok', true);
end $$;

-- p_new_version: set when the client has uploaded new text bytes as "<id>/v<expected+1>"
create or replace function public.commit_edit(
  p_id bigint, p_name text, p_category text, p_expected int, p_new_version int default null) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); d public.documents; denial jsonb; notes text[] := '{}'; o storage.objects;
begin
  if u.id is null then return private.gone(); end if;
  denial := private.gate(u, p_id, 'CHANGE', 'edit');
  if denial is not null then return denial; end if;
  select * into d from public.documents where id = p_id;
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
  if p_new_version is not null then
    if p_new_version <> d.version + 1 or d.ext not in ('txt','md','csv','json') then return private.invalid('Invalid version.'); end if;
    select * into o from storage.objects where bucket_id = 'vault' and name = d.id || '/v' || p_new_version;
    if o.id is null then return private.invalid('The new version did not arrive. Please try again.'); end if;
    notes := array_append(notes, 'text changed');
  end if;
  if p_name <> d.name then notes := array_append(notes, 'renamed from ' || d.name); end if;
  if p_category <> d.category then notes := array_append(notes, 'category ' || d.category || ' -> ' || p_category); end if;
  if cardinality(notes) = 0 then return jsonb_build_object('ok', true, 'changed', false); end if;
  update public.documents
     set name = p_name, category = p_category, modified_at = now(),
         version = coalesce(p_new_version, version),
         size = greatest(coalesce((o.metadata->>'size')::int, size), 1)
   where id = d.id;
  perform private.log(u.id, 'CHANGE', d.id, 'ALLOWED',
    array_to_string(notes, '; ') || ' (v' || coalesce(p_new_version, d.version) || ')');
  return jsonb_build_object('ok', true, 'changed', true);
end $$;

-- returns the storage paths so the client can delete the bytes afterwards
create or replace function public.remove_document(p_id bigint) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); d public.documents; denial jsonb; paths text[];
begin
  if u.id is null then return private.gone(); end if;
  denial := private.gate(u, p_id, 'DELETE', 'owner');
  if denial is not null then return denial; end if;
  select * into d from public.documents where id = p_id;
  select coalesce(array_agg(name), '{}') into paths from storage.objects
   where bucket_id = 'vault' and name like (d.id::text || '/%');
  perform private.log(u.id, 'DELETE', d.id, 'ALLOWED', '');
  delete from public.documents where id = d.id;
  return jsonb_build_object('ok', true, 'paths', to_jsonb(paths));
end $$;

create or replace function public.set_visibility(p_id bigint, p_v text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); denial jsonb;
begin
  if u.id is null then return private.gone(); end if;
  denial := private.gate(u, p_id, 'VISIBILITY', 'owner');
  if denial is not null then return denial; end if;
  if p_v not in ('everyone','private') then return private.invalid('Invalid choice.'); end if;
  update public.documents set visibility = p_v where id = p_id;
  perform private.log(u.id, 'VISIBILITY', p_id, 'ALLOWED', 'now ' || p_v);
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.grant_access(p_id bigint, p_user uuid, p_perm text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); denial jsonb; t public.profiles;
begin
  if u.id is null then return private.gone(); end if;
  denial := private.gate(u, p_id, 'PERMISSION_GRANT', 'owner');
  if denial is not null then return denial; end if;
  select * into t from public.profiles where id = p_user;
  if t.id is null or not t.approved or not t.active or t.id = u.id then return private.invalid('Choose another active person.'); end if;
  if p_perm not in ('read','edit') then return private.invalid('Permission must be read or edit.'); end if;
  if p_perm = 'edit' and t.role <> 'owner' then return private.invalid('Edit access can only go to document owners.'); end if;
  insert into public.doc_grants(doc_id, user_id, perm) values (p_id, t.id, p_perm)
  on conflict (doc_id, user_id) do update set perm = excluded.perm;
  perform private.log(u.id, 'PERMISSION_GRANT', p_id, 'ALLOWED', t.name || ': ' || p_perm);
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.revoke_access(p_id bigint, p_user uuid) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); denial jsonb; t public.profiles;
begin
  if u.id is null then return private.gone(); end if;
  denial := private.gate(u, p_id, 'PERMISSION_REVOKE', 'owner');
  if denial is not null then return denial; end if;
  select * into t from public.profiles where id = p_user;
  if t.id is null or not exists (select 1 from public.doc_grants where doc_id = p_id and user_id = t.id) then
    return private.invalid('That person has no grant on this document.');
  end if;
  delete from public.doc_grants where doc_id = p_id and user_id = t.id;
  perform private.log(u.id, 'PERMISSION_REVOKE', p_id, 'ALLOWED', t.name);
  return jsonb_build_object('ok', true);
end $$;

-- ---------------- administrator duties (never document contents) ----------------
create or replace function public.admin_overview() returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me();
begin
  if u.id is null then return private.gone(); end if;
  if u.role <> 'admin' then return private.deny(u.id, 'ADMIN_VIEW', null, 'Administrators only.'); end if;
  return jsonb_build_object(
    'log', coalesce((select jsonb_agg(to_jsonb(l)) from (select * from public.audit_log order by seq desc limit 200) l), '[]'::jsonb),
    'log_count', (select count(*) from public.audit_log),
    'register', coalesce((select jsonb_agg(jsonb_build_object('id', d.id, 'name', d.name, 'owner', d.owner_id,
                  'category', d.category, 'visibility', d.visibility,
                  'acl', coalesce((select jsonb_object_agg(g.user_id::text, g.perm) from public.doc_grants g where g.doc_id = d.id), '{}'::jsonb))
                  order by d.id) from public.documents d where d.ready), '[]'::jsonb),
    'users', coalesce((select jsonb_agg(private.brief(p) order by p.created_at) from public.profiles p), '[]'::jsonb));
end $$;

create or replace function public.decide(p_target uuid, p_approve boolean) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); t public.profiles;
begin
  if u.id is null then return private.gone(); end if;
  if u.role <> 'admin' then
    return private.deny(u.id, case when p_approve then 'APPROVE' else 'REJECT' end, null, 'Administrators only.');
  end if;
  select * into t from public.profiles where id = p_target and not approved;
  if t.id is null then return private.invalid('No such pending registration.'); end if;
  perform private.log(u.id, case when p_approve then 'APPROVE' else 'REJECT' end, null, 'ALLOWED', t.name || ' (' || t.role || ')');
  if p_approve then
    update public.profiles set approved = true where id = t.id;
  else
    delete from auth.users where id = t.id;           -- cascades to the profile
  end if;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.set_role(p_target uuid, p_role text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); t public.profiles;
begin
  if u.id is null then return private.gone(); end if;
  if u.role <> 'admin' then return private.deny(u.id, 'ROLE_CHANGE', null, 'Administrators only.'); end if;
  select * into t from public.profiles where id = p_target and approved and role <> 'admin';
  if t.id is null or p_role not in ('owner','viewer') then return private.invalid('Invalid role change.'); end if;
  if t.role = 'owner' and p_role = 'viewer' and exists (select 1 from public.documents where owner_id = t.id) then
    return private.invalid(t.name || ' still owns documents. They must delete them first.');
  end if;
  update public.profiles set role = p_role where id = t.id;
  perform private.log(u.id, 'ROLE_CHANGE', null, 'ALLOWED', t.name || ': ' || t.role || ' -> ' || p_role);
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.set_active(p_target uuid, p_on boolean) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); t public.profiles;
begin
  if u.id is null then return private.gone(); end if;
  if u.role <> 'admin' then return private.deny(u.id, 'ACCOUNT', null, 'Administrators only.'); end if;
  select * into t from public.profiles where id = p_target and approved and role <> 'admin';
  if t.id is null then return private.invalid('Invalid account.'); end if;
  update public.profiles set active = coalesce(p_on, false) where id = t.id;
  update auth.users set banned_until = case when coalesce(p_on, false) then null else now() + interval '100 years' end where id = t.id;
  if not coalesce(p_on, false) then delete from auth.sessions where user_id = t.id; end if;
  perform private.log(u.id, 'ACCOUNT', null, 'ALLOWED', t.name || ': ' || case when coalesce(p_on, false) then 'reactivated' else 'deactivated' end);
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.verify_log() returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); r public.audit_log; prev text := repeat('0', 64); last bigint := 0; n bigint := 0; total bigint;
begin
  if u.id is null then return private.gone(); end if;
  if u.role <> 'admin' then return private.deny(u.id, 'VERIFY', null, 'Administrators only.'); end if;
  select count(*) into total from public.audit_log;
  for r in select * from public.audit_log order by seq loop
    n := n + 1;
    if r.prev <> prev or r.seq <> last + 1 or private.seal(r, prev) <> r.hash then
      perform private.log(u.id, 'VERIFY', null, 'ALLOWED', 'broken at ' || r.seq);
      return jsonb_build_object('ok', false, 'checked', total, 'brokenAt', r.seq);
    end if;
    prev := r.hash; last := r.seq;
  end loop;
  perform private.log(u.id, 'VERIFY', null, 'ALLOWED', 'intact, ' || n || ' entries');
  return jsonb_build_object('ok', true, 'checked', n, 'head', prev);
end $$;

-- ---------------------------------------------------------------------
-- Function privileges: signed-in users only, never anonymous
-- ---------------------------------------------------------------------
revoke execute on all functions in schema public  from public, anon;
grant  execute on all functions in schema public  to authenticated;
revoke execute on all functions in schema private from public;
grant  execute on function private.my_access(bigint), private.can_write(bigint),
                           private.doc_exists(bigint), private.doc_of(text) to authenticated;

-- ---------------------------------------------------------------------
-- Storage: private bucket + policies that reuse the same access rules
-- ---------------------------------------------------------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('vault', 'vault', false, 1048576,
        array['text/plain','text/markdown','text/csv','application/json','application/pdf','image/png'])
on conflict (id) do update
  set public = false, file_size_limit = 1048576,
      allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "vault read"   on storage.objects;
drop policy if exists "vault upload" on storage.objects;
drop policy if exists "vault delete" on storage.objects;

create policy "vault read" on storage.objects for select to authenticated
using (bucket_id = 'vault' and (
  private.my_access(private.doc_of(name)) is not null or private.can_write(private.doc_of(name))));

create policy "vault upload" on storage.objects for insert to authenticated
with check (bucket_id = 'vault' and private.doc_of(name) is not null and private.can_write(private.doc_of(name)));

-- deleting is allowed for owners/editors, and for leftovers of documents that no longer exist
create policy "vault delete" on storage.objects for delete to authenticated
using (bucket_id = 'vault' and private.doc_of(name) is not null and (
  private.can_write(private.doc_of(name)) or not private.doc_exists(private.doc_of(name))));

-- =====================================================================
-- FIRST ADMIN (after you have signed up once through the app):
--   update public.profiles set role = 'admin', approved = true where username = 'your-username';
-- =====================================================================
