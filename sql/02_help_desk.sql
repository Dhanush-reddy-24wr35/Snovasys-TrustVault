-- =====================================================================
-- TrustVault: owner teams + help desk
-- Run ONCE in Supabase: SQL Editor -> New query -> paste all -> Run.
-- It sits on top of schema.sql (do NOT run schema.sql again).
--
-- Rules it adds
--   * A viewer belongs to ONE owner (profiles.owner_id). Approving a viewer
--     now requires choosing that owner. Owners need no owner.
--   * Help desk: a viewer can only write to their own owner; an owner can only
--     write to the administrators; administrators answer owners and cannot
--     raise requests. A viewer can never reach an administrator.
--   * An administrator only sees requests addressed to administrators, never
--     the conversations between a viewer and their owner.
--   * Every action re-checks the caller on the server and is logged;
--     refused attempts are logged as DENIED (same pattern as schema.sql).
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. Owner of a viewer
-- ---------------------------------------------------------------------
alter table public.profiles
  add column if not exists owner_id uuid references public.profiles(id) on delete set null;
create index if not exists profiles_owner_idx on public.profiles(owner_id);

-- ---------------------------------------------------------------------
-- 2. Help desk tables (locked: no direct access, only the functions below)
-- ---------------------------------------------------------------------
create table if not exists public.help_tickets (
  id         bigint generated always as identity primary key,
  from_id    uuid not null references public.profiles(id) on delete cascade,
  to_role    text not null check (to_role in ('owner','admin')),
  to_id      uuid references public.profiles(id) on delete set null,   -- the owner for viewer requests; null = any administrator
  subject    text not null check (char_length(subject) between 3 and 120),
  category   text not null default 'General' check (category in ('General','Access','Document','Upload','Account')),
  priority   text not null default 'normal'  check (priority in ('normal','urgent')),
  status     text not null default 'open'    check (status in ('open','answered','resolved')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists help_tickets_from_idx on public.help_tickets(from_id);
create index if not exists help_tickets_to_idx   on public.help_tickets(to_id);

create table if not exists public.help_messages (
  id         bigint generated always as identity primary key,
  ticket_id  bigint not null references public.help_tickets(id) on delete cascade,
  author_id  uuid   not null references public.profiles(id) on delete cascade,
  body       text   not null check (char_length(body) between 1 and 2000),
  created_at timestamptz not null default now()
);
create index if not exists help_messages_ticket_idx on public.help_messages(ticket_id);

alter table public.help_tickets  enable row level security;
alter table public.help_messages enable row level security;
revoke all on public.help_tickets, public.help_messages from anon, authenticated;

-- may this person see / answer this request?
create or replace function private.help_can(t public.help_tickets, u public.profiles) returns boolean
language sql stable set search_path = '' as $$
  select t.from_id = u.id
      or (t.to_role = 'owner' and t.to_id = u.id and u.role = 'owner')
      or (t.to_role = 'admin' and u.role = 'admin') $$;
revoke execute on function private.help_can(public.help_tickets, public.profiles) from public;

-- ---------------------------------------------------------------------
-- 3. Existing functions, updated
-- ---------------------------------------------------------------------
-- me() and login_check() now also return the caller's owner_id
create or replace function public.me() returns jsonb
language plpgsql stable security definer set search_path = '' as $$
declare u public.profiles := private.me();
begin
  if u.id is null then return private.gone(); end if;
  return private.brief(u) || jsonb_build_object('owner_id', u.owner_id);
end $$;

create or replace function public.login_check() returns jsonb
language plpgsql security definer set search_path = '' as $$
declare p public.profiles;
begin
  select * into p from public.profiles where id = auth.uid();
  if p.id is null then return private.deny(null, 'LOGIN', null, 'no profile for this account', 'Invalid credentials'); end if;
  if not p.approved then return private.deny(p.id, 'LOGIN', null, 'not yet approved', 'Your registration is waiting for an administrator to approve it.'); end if;
  if not p.active then return private.deny(p.id, 'LOGIN', null, 'account deactivated', 'This account has been deactivated.'); end if;
  perform private.log(p.id, 'LOGIN', null, 'ALLOWED', '');
  return private.brief(p) || jsonb_build_object('owner_id', p.owner_id);
end $$;

-- approving a VIEWER now requires choosing the owner they will belong to
drop function if exists public.decide(uuid, boolean);
create or replace function public.decide(p_target uuid, p_approve boolean, p_owner uuid default null) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); t public.profiles; o public.profiles;
begin
  if u.id is null then return private.gone(); end if;
  if u.role <> 'admin' then
    return private.deny(u.id, case when p_approve then 'APPROVE' else 'REJECT' end, null, 'Administrators only.');
  end if;
  select * into t from public.profiles where id = p_target and not approved;
  if t.id is null then return private.invalid('No such pending registration.'); end if;
  if p_approve and t.role = 'viewer' then
    select * into o from public.profiles where id = p_owner and role = 'owner' and approved and active;
    if o.id is null then return private.invalid('Choose the owner this viewer will belong to.'); end if;
  end if;
  perform private.log(u.id, case when p_approve then 'APPROVE' else 'REJECT' end, null, 'ALLOWED',
    t.name || ' (' || t.role || ')' || case when o.id is not null then ' -> team of ' || o.name else '' end);
  if p_approve then
    update public.profiles set approved = true, owner_id = case when t.role = 'viewer' then o.id end where id = t.id;
  else
    delete from auth.users where id = t.id;           -- cascades to the profile
  end if;
  return jsonb_build_object('ok', true);
end $$;

-- role changes keep teams consistent
create or replace function public.set_role(p_target uuid, p_role text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); t public.profiles;
begin
  if u.id is null then return private.gone(); end if;
  if u.role <> 'admin' then return private.deny(u.id, 'ROLE_CHANGE', null, 'Administrators only.'); end if;
  select * into t from public.profiles where id = p_target and approved and role <> 'admin';
  if t.id is null or p_role not in ('owner','viewer') then return private.invalid('Invalid role change.'); end if;
  if t.role = 'owner' and p_role = 'viewer' then
    if exists (select 1 from public.documents where owner_id = t.id) then
      return private.invalid(t.name || ' still owns documents. They must delete them first.');
    end if;
    if exists (select 1 from public.profiles where owner_id = t.id) then
      return private.invalid(t.name || ' still has team members. Assign them to another owner first.');
    end if;
  end if;
  update public.profiles set role = p_role, owner_id = null where id = t.id;   -- a new viewer needs an owner assigned
  perform private.log(u.id, 'ROLE_CHANGE', null, 'ALLOWED', t.name || ': ' || t.role || ' -> ' || p_role);
  return jsonb_build_object('ok', true);
end $$;

-- deactivating an owner releases their team (those viewers wait for a new owner)
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
  if not coalesce(p_on, false) then
    delete from auth.sessions where user_id = t.id;
    update public.profiles set owner_id = null where owner_id = t.id;
  end if;
  perform private.log(u.id, 'ACCOUNT', null, 'ALLOWED', t.name || ': ' || case when coalesce(p_on, false) then 'reactivated' else 'deactivated' end);
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------------
-- 4. New functions
-- ---------------------------------------------------------------------
-- administrator: who belongs to whom (merged into the Accounts table by the page)
create or replace function public.admin_people() returns jsonb
language plpgsql stable security definer set search_path = '' as $$
declare u public.profiles := private.me();
begin
  if u.id is null then return private.gone(); end if;
  if u.role <> 'admin' then return private.deny(u.id, 'ADMIN_VIEW', null, 'Administrators only.'); end if;
  return coalesce((select jsonb_agg(jsonb_build_object('id', p.id, 'owner_id', p.owner_id,
            'team', (select count(*) from public.profiles m where m.owner_id = p.id and m.approved))) from public.profiles p), '[]'::jsonb);
end $$;

create or replace function public.assign_owner(p_target uuid, p_owner uuid) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); t public.profiles; o public.profiles;
begin
  if u.id is null then return private.gone(); end if;
  if u.role <> 'admin' then return private.deny(u.id, 'OWNER_ASSIGN', null, 'Administrators only.'); end if;
  select * into t from public.profiles where id = p_target and approved and role = 'viewer';
  if t.id is null then return private.invalid('Only approved viewers belong to an owner.'); end if;
  select * into o from public.profiles where id = p_owner and role = 'owner' and approved and active;
  if o.id is null then return private.invalid('Choose an active document owner.'); end if;
  update public.profiles set owner_id = o.id where id = t.id;
  perform private.log(u.id, 'OWNER_ASSIGN', null, 'ALLOWED', t.name || ' -> team of ' || o.name);
  return jsonb_build_object('ok', true);
end $$;

-- owner: the viewers who belong to me
create or replace function public.my_team() returns jsonb
language plpgsql stable security definer set search_path = '' as $$
declare u public.profiles := private.me();
begin
  if u.id is null then return private.gone(); end if;
  if u.role <> 'owner' then return private.deny(u.id, 'TEAM', null, 'Only document owners have a team.'); end if;
  return coalesce((select jsonb_agg(jsonb_build_object('id', p.id, 'name', p.name, 'username', p.username,
            'active', p.active, 'joined', p.created_at) order by p.name)
          from public.profiles p where p.owner_id = u.id and p.approved), '[]'::jsonb);
end $$;

-- every request I may see, with its conversation
create or replace function public.help_list() returns jsonb
language plpgsql stable security definer set search_path = '' as $$
declare u public.profiles := private.me();
begin
  if u.id is null then return private.gone(); end if;
  return coalesce((
    select jsonb_agg(jsonb_build_object(
        'id', t.id, 'from', t.from_id, 'to_role', t.to_role, 'to', t.to_id, 'subject', t.subject,
        'category', t.category, 'priority', t.priority, 'status', t.status,
        'created', t.created_at, 'updated', t.updated_at,
        'messages', coalesce((select jsonb_agg(jsonb_build_object('id', m.id, 'author', m.author_id, 'body', m.body, 'at', m.created_at) order by m.id)
                              from public.help_messages m where m.ticket_id = t.id), '[]'::jsonb)
      ) order by t.updated_at desc)
    from public.help_tickets t where private.help_can(t, u)), '[]'::jsonb);
end $$;

-- the recipient is decided HERE from the caller's role; the caller cannot choose it
create or replace function public.help_create(
  p_subject text, p_body text, p_category text default 'General', p_priority text default 'normal') returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); rcpt_role text; rcpt uuid; new_id bigint;
begin
  if u.id is null then return private.gone(); end if;
  if u.role = 'admin' then
    return private.deny(u.id, 'HELP_NEW', null, 'Administrators answer requests; they do not raise them.');
  end if;
  if char_length(btrim(coalesce(p_subject, ''))) not between 3 and 120 then return private.invalid('Give the request a subject (3-120 characters).'); end if;
  if char_length(btrim(coalesce(p_body, ''))) not between 1 and 2000 then return private.invalid('Write a message (up to 2000 characters).'); end if;
  if coalesce(p_category, '') not in ('General','Access','Document','Upload','Account') then return private.invalid('Choose a category.'); end if;
  if coalesce(p_priority, '') not in ('normal','urgent') then return private.invalid('Choose a priority.'); end if;
  if u.role = 'viewer' then
    rcpt_role := 'owner';
    select o.id into rcpt from public.profiles o where o.id = u.owner_id and o.role = 'owner' and o.approved and o.active;
    if rcpt is null then
      perform private.log(u.id, 'HELP_NEW', null, 'DENIED', 'no owner assigned');
      return private.invalid('The administrator has not assigned any owner to you yet, so please wait.');
    end if;
  else
    rcpt_role := 'admin'; rcpt := null;
  end if;
  insert into public.help_tickets(from_id, to_role, to_id, subject, category, priority)
  values (u.id, rcpt_role, rcpt, btrim(p_subject), p_category, p_priority) returning id into new_id;
  insert into public.help_messages(ticket_id, author_id, body) values (new_id, u.id, btrim(p_body));
  perform private.log(u.id, 'HELP_NEW', null, 'ALLOWED', 'request #' || new_id || ' to ' || rcpt_role || ' (' || p_priority || ')');
  return jsonb_build_object('ok', true, 'id', new_id);
end $$;

create or replace function public.help_reply(p_ticket bigint, p_body text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); t public.help_tickets;
begin
  if u.id is null then return private.gone(); end if;
  select * into t from public.help_tickets where id = p_ticket;
  if t.id is null or not private.help_can(t, u) then
    return private.deny(u.id, 'HELP_REPLY', null, 'request ' || coalesce(p_ticket::text, 'null') || ' is not yours', 'That request is not available to you.');
  end if;
  if char_length(btrim(coalesce(p_body, ''))) not between 1 and 2000 then return private.invalid('Write a reply (up to 2000 characters).'); end if;
  if t.status = 'resolved' then return private.invalid('This request is resolved. Reopen it to reply.'); end if;
  insert into public.help_messages(ticket_id, author_id, body) values (t.id, u.id, btrim(p_body));
  update public.help_tickets
     set status = case when t.from_id = u.id then 'open' else 'answered' end, updated_at = now()
   where id = t.id;
  perform private.log(u.id, 'HELP_REPLY', null, 'ALLOWED', 'request #' || t.id);
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.help_status(p_ticket bigint, p_status text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare u public.profiles := private.me(); t public.help_tickets;
begin
  if u.id is null then return private.gone(); end if;
  select * into t from public.help_tickets where id = p_ticket;
  if t.id is null or not private.help_can(t, u) then
    return private.deny(u.id, 'HELP_STATUS', null, 'request ' || coalesce(p_ticket::text, 'null') || ' is not yours', 'That request is not available to you.');
  end if;
  if coalesce(p_status, '') not in ('open','resolved') then return private.invalid('Invalid status.'); end if;
  update public.help_tickets set status = p_status, updated_at = now() where id = t.id;
  perform private.log(u.id, 'HELP_STATUS', null, 'ALLOWED', 'request #' || t.id || ' -> ' || p_status);
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------------
-- 5. Privileges: signed-in users only, never anonymous
-- ---------------------------------------------------------------------
revoke execute on function
  public.me(), public.login_check(), public.decide(uuid, boolean, uuid), public.set_role(uuid, text),
  public.set_active(uuid, boolean), public.admin_people(), public.assign_owner(uuid, uuid), public.my_team(),
  public.help_list(), public.help_create(text, text, text, text), public.help_reply(bigint, text), public.help_status(bigint, text)
  from public, anon;
grant execute on function
  public.me(), public.login_check(), public.decide(uuid, boolean, uuid), public.set_role(uuid, text),
  public.set_active(uuid, boolean), public.admin_people(), public.assign_owner(uuid, uuid), public.my_team(),
  public.help_list(), public.help_create(text, text, text, text), public.help_reply(bigint, text), public.help_status(bigint, text)
  to authenticated;

-- ---------------------------------------------------------------------
-- OPTIONAL, only if you already have approved viewers with no owner:
-- put them all under the first active owner (or assign them one by one in
-- the app: Administration -> Accounts).
--   update public.profiles
--      set owner_id = (select id from public.profiles where role = 'owner' and approved and active order by created_at limit 1)
--    where role = 'viewer' and approved and owner_id is null;
-- ---------------------------------------------------------------------
