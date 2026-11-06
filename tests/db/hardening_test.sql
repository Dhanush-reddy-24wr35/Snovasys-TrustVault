-- Database-level authorization and audit tests (plain SQL, no Supabase needed).
-- Needs: stubs.sql, 01_schema.sql, 02_help_desk.sql, 03_hardening.sql loaded into an empty database.
-- Run:   psql -v ON_ERROR_STOP=1 -d tv -f tests/db/hardening_test.sql
-- Prints PASS/FAIL per check and a summary (run.sh turns any FAIL into a non-zero exit code).
\set ON_ERROR_STOP 0
create schema if not exists t; grant usage on schema t to public;
drop table if exists t.res; create table t.res(n serial, name text, pass boolean);
create or replace function t.as_user(u uuid) returns void language plpgsql as $$
begin perform set_config('request.jwt.claim.sub', u::text, true); execute 'set local role authenticated'; end $$;
create or replace function t.as_anon() returns void language plpgsql as $$
begin perform set_config('request.jwt.claim.sub', '', true); execute 'set local role anon'; end $$;
create or replace function t.su() returns void language plpgsql as $$ begin execute 'reset role'; end $$;
create or replace function t.chk(p_name text, p_pass boolean) returns void language plpgsql security definer set search_path = '' as $$
begin insert into t.res(name, pass) values (p_name, coalesce(p_pass, false)); end $$;
create or replace function t.b64(p text) returns text language sql as $$ select encode(convert_to(p, 'UTF8'), 'base64') $$;

do $$
declare
  admin_id uuid := gen_random_uuid(); alice uuid := gen_random_uuid(); bob uuid := gen_random_uuid(); carol uuid := gen_random_uuid();
  docid bigint; r jsonb; n1 bigint; n2 bigint; pdf text; png text; big text; k int; thrown boolean; tk bigint;
begin
  -- people: admin, alice (owner), bob (owner), carol (viewer of alice)
  insert into auth.users(id, email, raw_user_meta_data) values
    (admin_id, 'admin@t.test', '{"name":"Ada Admin","username":"ada","role":"viewer"}'),
    (alice,    'alice@t.test', '{"name":"Alice Owner","username":"alice","role":"owner"}'),
    (bob,      'bob@t.test',   '{"name":"Bob Owner","username":"bob","role":"owner"}'),
    (carol,    'carol@t.test', '{"name":"Carol Viewer","username":"carol","role":"viewer"}');
  update public.profiles set role = 'admin', approved = true where id = admin_id;
  update public.profiles set approved = true where id in (alice, bob);
  update public.profiles set approved = true, owner_id = alice where id = carol;

  -- ---------- upload as alice
  perform t.as_user(alice);
  r := public.create_document('plan.txt', 'Finance', 'private', '{}', t.b64('secret plan'));
  docid := (r->>'id')::bigint;
  perform t.su(); perform t.chk('alice can upload a text document', docid is not null);

  -- ---------- bob (another owner) cannot touch alice's private document
  perform t.as_user(bob);
  perform t.chk('bob does not see it in his list', (select count(*) from jsonb_array_elements(public.list_documents())) = 0);
  r := public.inspect_document(docid);                         perform t.chk('bob cannot read',          r->>'ok' = 'false');
  r := public.download_document(docid);                        perform t.chk('bob cannot download',      r->>'ok' = 'false');
  r := public.commit_edit(docid, 'plan.txt', 'Finance', 1, 'hacked'); perform t.chk('bob cannot edit',   r->>'ok' = 'false');
  r := public.replace_file(docid, 1, t.b64('x'));              perform t.chk('bob cannot replace file',  r->>'ok' = 'false');
  r := public.remove_document(docid);                          perform t.chk('bob cannot delete',        r->>'ok' = 'false');
  r := public.set_visibility(docid, 'everyone');               perform t.chk('bob cannot change visibility', r->>'ok' = 'false');
  r := public.grant_access(docid, bob, 'edit');                perform t.chk('bob cannot grant himself access', r->>'ok' = 'false');
  r := public.revoke_access(docid, alice);                     perform t.chk('bob cannot revoke alice', r->>'ok' = 'false');
  r := public.doc_details(docid);                              perform t.chk('bob cannot read details', r->>'ok' = 'false');
  perform t.su();
  select count(*) into n1 from public.audit_log where actor = bob and outcome = 'DENIED' and doc = docid;
  perform t.chk('every refusal by bob is in the audit log (>= 9)', n1 >= 9);
  perform t.chk('document is still intact after the attacks',
    (select version from public.documents where id = docid) = 1 and (select convert_from(content,'UTF8') from public.doc_files where doc_id = docid) = 'secret plan');

  -- ---------- admin is not a back door
  perform t.as_user(admin_id);
  r := public.inspect_document(docid);  perform t.chk('admin cannot read contents', r->>'ok' = 'false');
  r := public.download_document(docid); perform t.chk('admin cannot download',     r->>'ok' = 'false');
  r := public.admin_overview();       perform t.chk('admin still sees the register', jsonb_array_length(r->'register') >= 1);
  perform t.su();

  -- ---------- viewer cannot upload; owner-only actions
  perform t.as_user(carol);
  r := public.create_document('v.txt', 'Other', 'everyone', '{}', t.b64('x')); perform t.chk('viewer cannot upload', r->>'ok' = 'false');
  perform t.su();

  -- ---------- grants and immediate revocation
  perform t.as_user(alice); r := public.grant_access(docid, bob, 'read'); perform t.su();
  perform t.chk('alice can grant read', r->>'ok' = 'true');
  perform t.as_user(bob);
  r := public.inspect_document(docid);  perform t.chk('bob can read once granted', r->>'text' = 'secret plan');
  r := public.commit_edit(docid, 'plan.txt', 'Finance', 1, 'x'); perform t.chk('read grant does not allow edit', r->>'ok' = 'false');
  perform t.su();
  perform t.as_user(alice); r := public.revoke_access(docid, bob); perform t.su();
  perform t.as_user(bob);
  r := public.inspect_document(docid);  perform t.chk('revocation is immediate (read)',     r->>'ok' = 'false');
  r := public.download_document(docid); perform t.chk('revocation is immediate (download)', r->>'ok' = 'false');
  perform t.su();
  perform t.as_user(alice); r := public.grant_access(docid, carol, 'edit'); perform t.su();
  perform t.chk('edit access cannot go to a viewer', r->>'ok' = 'false');
  perform t.as_user(alice); r := public.grant_access(docid, bob, 'edit'); perform t.su();
  perform t.as_user(bob); r := public.commit_edit(docid, 'plan.txt', 'Finance', 1, 'bob edit'); perform t.su();
  perform t.chk('edit grant lets bob edit', r->>'ok' = 'true' and (r->>'version')::int = 2);
  perform t.as_user(alice); r := public.revoke_access(docid, bob); perform t.su();
  perform t.as_user(bob); r := public.commit_edit(docid, 'plan.txt', 'Finance', 2, 'again'); perform t.su();
  perform t.chk('revoked editor cannot edit', r->>'ok' = 'false');
  perform t.as_user(alice); r := public.commit_edit(docid, 'plan.txt', 'Finance', 1, 'stale'); perform t.su();
  perform t.chk('stale version is refused', r->>'ok' = 'false');

  -- ---------- no direct table access
  for tk in 1..4 loop
    thrown := false;
    begin
      perform t.as_user(alice);
      if tk = 1 then perform 1 from public.documents limit 1;
      elsif tk = 2 then perform 1 from public.doc_files limit 1;
      elsif tk = 3 then perform 1 from public.audit_log limit 1;
      else delete from public.doc_grants; end if;
    exception when insufficient_privilege then thrown := true; end;
    perform t.su();
    perform t.chk('direct table access refused (#' || tk || ')', thrown);
  end loop;
  begin perform t.as_anon(); perform public.list_documents(); thrown := false;
  exception when insufficient_privilege then thrown := true; end; perform t.su();
  perform t.chk('signed-out caller cannot call list_documents', thrown);

  -- ---------- reading is always audited, no quiet option
  select count(*) into n1 from public.audit_log where action = 'READ' and actor = alice and doc = docid;
  perform t.as_user(alice); r := public.inspect_document(docid); perform t.su();
  select count(*) into n2 from public.audit_log where action = 'READ' and actor = alice and doc = docid;
  perform t.chk('reading writes a READ entry', n2 = n1 + 1);
  begin perform t.as_user(alice); perform public.inspect_document(docid, true); thrown := false;
  exception when undefined_function then thrown := true; end; perform t.su();
  perform t.chk('there is no quiet read any more', thrown);
  select count(*) into n1 from public.audit_log where action = 'DOWNLOAD' and actor = alice;
  perform t.as_user(alice); r := public.download_document(docid); perform t.su();
  select count(*) into n2 from public.audit_log where action = 'DOWNLOAD' and actor = alice;
  perform t.chk('download writes a DOWNLOAD entry and returns the bytes', n2 = n1 + 1 and convert_from(decode(r->>'data','base64'),'UTF8') = 'bob edit');

  -- ---------- server-side upload validation
  pdf := encode('%PDF-1.4 test'::bytea, 'base64');
  png := encode('\x89504e470d0a1a0a0000'::bytea, 'base64');
  big := replace(encode(repeat('a', 3145729)::bytea, 'base64'), E'\n', '');
  perform t.as_user(alice);
  r := public.create_document('a.pdf', 'Other', 'private', '{}', pdf);             perform t.chk('real PDF accepted', r->>'ok' = 'true');
  r := public.create_document('b.png', 'Other', 'private', '{}', png);             perform t.chk('real PNG accepted', r->>'ok' = 'true');
  r := public.create_document('fake.pdf', 'Other', 'private', '{}', t.b64('hello')); perform t.chk('fake PDF rejected',  r->>'ok' = 'false');
  r := public.create_document('fake.png', 'Other', 'private', '{}', t.b64('hello')); perform t.chk('fake PNG rejected',  r->>'ok' = 'false');
  r := public.create_document('bad.json', 'Other', 'private', '{}', t.b64('{nope')); perform t.chk('invalid JSON rejected', r->>'ok' = 'false');
  r := public.create_document('good.json', 'Other', 'private', '{}', t.b64('{"a":1}')); perform t.chk('valid JSON accepted', r->>'ok' = 'true');
  r := public.create_document('bin.txt', 'Other', 'private', '{}', encode('\x68690068'::bytea, 'base64')); perform t.chk('NUL byte in text rejected', r->>'ok' = 'false');
  r := public.create_document('utf.txt', 'Other', 'private', '{}', encode('\xfffe41'::bytea, 'base64')); perform t.chk('invalid UTF-8 rejected', r->>'ok' = 'false');
  r := public.create_document('huge.txt', 'Other', 'private', '{}', big);           perform t.chk('over 3 MB rejected', r->>'ok' = 'false');
  r := public.create_document('x.exe', 'Other', 'private', '{}', t.b64('MZ'));      perform t.chk('.exe rejected', r->>'ok' = 'false');
  r := public.create_document('../evil.txt', 'Other', 'private', '{}', t.b64('x')); perform t.chk('path traversal name rejected', r->>'ok' = 'false');
  r := public.create_document('empty.txt', 'Other', 'private', '{}', '');           perform t.chk('empty file rejected', r->>'ok' = 'false');
  r := public.create_document('ok3.txt', 'Other', 'private', '{}', replace(encode(repeat('a', 3145728)::bytea, 'base64'), E'\n', '')); perform t.chk('exactly 3 MB accepted', r->>'ok' = 'true');
  perform t.su();
  perform t.chk('rejected uploads are audited as DENIED', (select count(*) from public.audit_log where action = 'UPLOAD' and outcome = 'DENIED' and detail like 'rejected:%') >= 6);

  -- ---------- replace a PDF with a new version
  select id into docid from public.documents where name = 'a.pdf' and owner_id = alice;
  perform t.as_user(alice);
  r := public.replace_file(docid, 1, encode('%PDF-1.7 newer'::bytea, 'base64')); perform t.chk('PDF can be replaced', r->>'ok' = 'true' and (r->>'version')::int = 2);
  r := public.replace_file(docid, 2, png); perform t.chk('replacement must match the file type', r->>'ok' = 'false');
  perform t.su();
  perform t.chk('old version is gone, new one stored', (select count(*) from public.doc_files where doc_id = docid) = 1);

  -- ---------- delete removes everything
  perform t.as_user(alice); r := public.remove_document(docid); perform t.su();
  perform t.chk('owner can delete', r->>'ok' = 'true' and not exists (select 1 from public.doc_files where doc_id = docid));

  -- ---------- help desk reply rule
  perform t.as_user(carol);
  r := public.help_create('Need access please', 'Hello owner', 'Access', 'normal'); tk := (r->>'id')::bigint;
  r := public.help_reply(tk, 'any news?');   perform t.chk('requester cannot reply to their own message', r->>'ok' = 'false');
  perform t.su(); perform t.as_user(alice);
  r := public.help_reply(tk, 'here you go'); perform t.chk('owner can reply', r->>'ok' = 'true');
  perform t.su(); perform t.as_user(carol);
  r := public.help_reply(tk, 'thanks');      perform t.chk('requester can reply after an answer', r->>'ok' = 'true');
  perform t.su(); perform t.as_user(bob);
  r := public.help_reply(tk, 'let me in');   perform t.chk('another owner cannot join the thread', r->>'ok' = 'false');
  perform t.su();

  -- ---------- signed-out helpers
  perform t.as_anon();
  perform t.chk('username check works signed out', public.username_available('alice') = false and public.username_available('newname') = true);
  perform public.log_failed_login('alice@t.test', 'wrong email or password');
  perform public.log_failed_login('nobody@t.test', 'anything else');
  perform t.su();
  perform t.chk('failed sign-in is logged against the real user',
    exists (select 1 from public.audit_log where action = 'LOGIN' and outcome = 'DENIED' and actor = alice and detail like 'failed sign-in for alice@t.test%client-reported%'));
  perform t.chk('failed sign-in for an unknown email is logged too',
    exists (select 1 from public.audit_log where action = 'LOGIN' and outcome = 'DENIED' and actor is null and detail like 'failed sign-in for nobody@t.test%'));

  -- ---------- audit trail is append-only and verifiable
  for tk in 1..3 loop
    thrown := false;
    begin
      if tk = 1 then update public.audit_log set detail = 'edited' where seq = 1;
      elsif tk = 2 then delete from public.audit_log where seq = 1;
      else truncate public.audit_log; end if;
    exception when insufficient_privilege then thrown := true; end;
    perform t.chk('audit log refuses update/delete/truncate (#' || tk || ')', thrown);
  end loop;
  perform t.as_user(admin_id); r := public.verify_log(); perform t.su();
  perform t.chk('chain verifies as intact', r->>'ok' = 'true');
  perform t.as_user(bob); r := public.verify_log(); perform t.su();
  perform t.chk('non-admin cannot verify', r->>'ok' = 'false');
  perform t.as_user(admin_id); r := public.admin_log(null, 5, 'DENIED', null); perform t.su();
  perform t.chk('admin log pages and filters', jsonb_array_length(r->'rows') = 5 and (r->>'more')::boolean and not exists (select 1 from jsonb_array_elements(r->'rows') x where x->>'outcome' <> 'DENIED'));
  perform t.as_user(bob); r := public.admin_log(); perform t.su();
  perform t.chk('non-admin cannot read the full log', r->>'ok' = 'false');

  -- ---------- flooding the log
  perform t.as_user(bob);
  for k in 1..150 loop perform public.inspect_document(999999); end loop;
  perform t.su();
  perform t.chk('flood is summarised (one RATE_LIMIT entry, bounded refusals)',
    (select count(*) from public.audit_log where actor = bob and action = 'RATE_LIMIT') = 1
    and (select count(*) from public.audit_log where actor = bob and outcome = 'DENIED' and ts > now() - interval '1 minute') <= 102);
  select max(id) into docid from public.documents where owner_id = alice;
  perform t.as_user(alice); r := public.inspect_document(docid); perform t.su();
  perform t.chk('real activity is still logged during a flood', exists (select 1 from public.audit_log where actor = alice and action = 'READ' and ts > now() - interval '1 minute'));
end $$;

-- ---------- removing the newest entries is detected (rolled back afterwards)
do $$
declare r jsonb; admin_id uuid; ok boolean;
begin
  select id into admin_id from public.profiles where role = 'admin' limit 1;
  begin
    alter table public.audit_log disable trigger audit_no_change;
    delete from public.audit_log where seq = (select max(seq) from public.audit_log);
    alter table public.audit_log enable trigger audit_no_change;
    perform t.as_user(admin_id); r := public.verify_log(); perform t.su();
    ok := r->>'ok' = 'false' and coalesce((r->>'truncated')::boolean, false);
    raise exception 'rollback-marker %', case when ok then 'yes' else 'no' end;
  exception when others then
    if sqlerrm like 'rollback-marker%' then ok := sqlerrm = 'rollback-marker yes'; else raise; end if;
  end;
  perform t.su();
  insert into t.res(name, pass) values ('deleting the newest entries is detected by verify_log', ok);
end $$;
do $$
declare r jsonb; admin_id uuid;
begin
  select id into admin_id from public.profiles where role = 'admin' limit 1;
  perform t.as_user(admin_id); r := public.verify_log(); perform t.su();
  insert into t.res(name, pass) values ('chain intact again after the test rollback', r->>'ok' = 'true');
end $$;

\echo
select case when pass then 'PASS' else 'FAIL' end as result, name from t.res order by n;
select count(*) filter (where pass) as passed, count(*) filter (where not pass) as failed from t.res;
