// Black-box tests through the public API, as real signed-in users, against a Supabase project.
// They create temporary users (and delete them afterwards). Use a TEST project, not production.
//   cp .env.example .env  (fill it in)   then   node --env-file=.env --test tests/api/
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createClient } from '@supabase/supabase-js';

const { SUPABASE_URL: URL_, SUPABASE_ANON_KEY: ANON, SUPABASE_SERVICE_ROLE_KEY: SERVICE } = process.env;
if (!URL_ || !ANON || !SERVICE) { console.error('Set SUPABASE_URL, SUPABASE_ANON_KEY and SUPABASE_SERVICE_ROLE_KEY.'); process.exit(1); }
const opts = { auth: { persistSession: false, autoRefreshToken: false } };
const svc = createClient(URL_, SERVICE, opts);
const run = Math.random().toString(36).slice(2, 8);
const b64 = (t) => Buffer.from(t).toString('base64');
const refused = (r) => r.error != null || (r.data && r.data.ok === false);
const rpc = (u, fn, args) => u.client.rpc(fn, args || {});
const made = [];

async function makeUser(label, role, ownerId = null) {
  const email = `${label}.${run}@trustvault.test`, password = `Test#${run}9x`;
  const { data, error } = await svc.auth.admin.createUser({
    email, password, email_confirm: true,
    user_metadata: { name: `${label} Test`, username: `${label}_${run}`, role: role === 'admin' ? 'viewer' : role },
  });
  assert.ifError(error);
  const id = data.user.id; made.push(id);
  const up = await svc.from('profiles').update({ role, approved: true, owner_id: ownerId }).eq('id', id);
  assert.ifError(up.error);
  const client = createClient(URL_, ANON, opts);
  const si = await client.auth.signInWithPassword({ email, password });
  assert.ifError(si.error);
  return { id, email, password, client };
}
// every audit entry for an actor+action(+doc), newest first
async function audit(actor, action, doc) {
  let q = svc.from('audit_log').select('seq,outcome,detail,doc').eq('actor', actor).eq('action', action).order('seq', { ascending: false });
  if (doc != null) q = q.eq('doc', doc);
  const { data, error } = await q; assert.ifError(error); return data;
}

let admin, alice, bob, carol, docId;
before(async () => {
  admin = await makeUser('admin', 'admin');
  alice = await makeUser('alice', 'owner');
  bob   = await makeUser('bob',   'owner');
  carol = await makeUser('carol', 'viewer', alice.id);
  const r = await rpc(alice, 'create_document', { p_name: 'plan.txt', p_category: 'Finance', p_visibility: 'private', p_editors: [], p_data: b64('secret plan') });
  assert.equal(r.data?.ok, true, JSON.stringify(r)); docId = r.data.id;
});
after(async () => {
  for (const u of [alice, bob]) await svc.from('documents').delete().eq('owner_id', u.id);
  for (const id of made) await svc.auth.admin.deleteUser(id).catch(() => {});
});

test('another owner cannot read, download, edit, replace, delete or share alice\'s private document', async () => {
  const attempts = {
    read:       await rpc(bob, 'inspect_document', { p_id: docId }),
    download:   await rpc(bob, 'download_document', { p_id: docId }),
    details:    await rpc(bob, 'doc_details', { p_id: docId }),
    edit:       await rpc(bob, 'commit_edit', { p_id: docId, p_name: 'plan.txt', p_category: 'Finance', p_expected: 1, p_text: 'hacked' }),
    replace:    await rpc(bob, 'replace_file', { p_id: docId, p_expected: 1, p_data: b64('x') }),
    remove:     await rpc(bob, 'remove_document', { p_id: docId }),
    visibility: await rpc(bob, 'set_visibility', { p_id: docId, p_v: 'everyone' }),
    grantSelf:  await rpc(bob, 'grant_access', { p_id: docId, p_user: bob.id, p_perm: 'edit' }),
  };
  for (const [k, r] of Object.entries(attempts)) assert.ok(refused(r), `${k} should be refused`);
  const list = await rpc(bob, 'list_documents');
  assert.equal(list.data.filter((d) => d.id === docId).length, 0, 'document must not be listed for bob');
  const rows = await audit(bob.id, 'READ', docId);
  assert.ok(rows.some((x) => x.outcome === 'DENIED'), 'bob\'s refused read must be audited');
});

test('refused attempts leave the document untouched', async () => {
  const r = await rpc(alice, 'inspect_document', { p_id: docId });
  assert.equal(r.data.text, 'secret plan');
  assert.equal(r.data.meta.version, 1);
});

test('an administrator cannot read document contents', async () => {
  assert.ok(refused(await rpc(admin, 'inspect_document', { p_id: docId })));
  assert.ok(refused(await rpc(admin, 'download_document', { p_id: docId })));
  const ov = await rpc(admin, 'admin_overview');
  assert.ok(ov.data.register.some((d) => d.id === docId), 'admin still sees the register entry');
});

test('a viewer cannot upload', async () => {
  const r = await rpc(carol, 'create_document', { p_name: 'v.txt', p_category: 'Other', p_visibility: 'everyone', p_editors: [], p_data: b64('x') });
  assert.ok(refused(r));
});

test('read access works, does not allow editing, and revocation is immediate', async () => {
  assert.equal((await rpc(alice, 'grant_access', { p_id: docId, p_user: bob.id, p_perm: 'read' })).data?.ok, true);
  const read = await rpc(bob, 'inspect_document', { p_id: docId });
  assert.equal(read.data?.text, 'secret plan');
  assert.ok(refused(await rpc(bob, 'commit_edit', { p_id: docId, p_name: 'plan.txt', p_category: 'Finance', p_expected: 1, p_text: 'x' })));
  assert.equal((await rpc(alice, 'revoke_access', { p_id: docId, p_user: bob.id })).data?.ok, true);
  assert.ok(refused(await rpc(bob, 'inspect_document', { p_id: docId })), 'read must fail right after revoke');
  assert.ok(refused(await rpc(bob, 'download_document', { p_id: docId })), 'download must fail right after revoke');
});

test('edit access can only go to owners, and it ends when revoked', async () => {
  assert.ok(refused(await rpc(alice, 'grant_access', { p_id: docId, p_user: carol.id, p_perm: 'edit' })), 'viewer cannot be an editor');
  assert.equal((await rpc(alice, 'grant_access', { p_id: docId, p_user: bob.id, p_perm: 'edit' })).data?.ok, true);
  const e = await rpc(bob, 'commit_edit', { p_id: docId, p_name: 'plan.txt', p_category: 'Finance', p_expected: 1, p_text: 'bob was here' });
  assert.equal(e.data?.ok, true); assert.equal(e.data.version, 2);
  assert.equal((await rpc(alice, 'revoke_access', { p_id: docId, p_user: bob.id })).data?.ok, true);
  assert.ok(refused(await rpc(bob, 'commit_edit', { p_id: docId, p_name: 'plan.txt', p_category: 'Finance', p_expected: 2, p_text: 'again' })));
  assert.ok(refused(await rpc(alice, 'commit_edit', { p_id: docId, p_name: 'plan.txt', p_category: 'Finance', p_expected: 1, p_text: 'stale' })), 'stale version refused');
});

test('there are no direct routes to tables or files', async () => {
  for (const t of ['documents', 'doc_files', 'doc_grants', 'audit_log', 'profiles', 'help_tickets']) {
    const r = await alice.client.from(t).select('*').limit(1);
    assert.ok(r.error, `${t} must not be readable directly`);
  }
  const bad = await alice.client.from('documents').update({ owner_id: bob.id }).eq('id', docId);
  assert.ok(bad.error, 'direct update must be refused');
  const dl = await bob.client.storage.from('vault').download(`${docId}/v1`);
  assert.ok(dl.error || !dl.data, 'direct storage download must fail');
  const up = await bob.client.storage.from('vault').upload(`${docId}/v9`, new Blob(['x']));
  assert.ok(up.error, 'direct storage upload must fail');
  const anon = createClient(URL_, ANON, opts);
  assert.ok((await anon.rpc('list_documents', {})).error, 'signed-out caller cannot list');
  assert.ok((await anon.rpc('inspect_document', { p_id: docId })).error, 'signed-out caller cannot read');
});

test('every read and download is audited (there is no quiet option)', async () => {
  const before = (await audit(alice.id, 'READ', docId)).length;
  await rpc(alice, 'inspect_document', { p_id: docId });
  assert.equal((await audit(alice.id, 'READ', docId)).length, before + 1);
  const quiet = await rpc(alice, 'inspect_document', { p_id: docId, p_quiet: true });
  assert.ok(quiet.error, 'p_quiet must not exist');
  const d0 = (await audit(alice.id, 'DOWNLOAD', docId)).length;
  const dl = await rpc(alice, 'download_document', { p_id: docId });
  assert.equal(Buffer.from(dl.data.data, 'base64').toString(), 'bob was here');
  assert.equal((await audit(alice.id, 'DOWNLOAD', docId)).length, d0 + 1);
});

test('uploads are validated by the server', async () => {
  const bad = [
    ['fake.pdf', b64('hello')], ['fake.png', b64('hello')], ['bad.json', b64('{nope')],
    ['x.exe', b64('MZ')], ['../evil.txt', b64('x')], ['empty.txt', ''],
    ['bin.txt', Buffer.from([0x68, 0x69, 0x00, 0x68]).toString('base64')],
    ['utf.txt', Buffer.from([0xff, 0xfe, 0x41]).toString('base64')],
    ['huge.txt', Buffer.alloc(3 * 1024 * 1024 + 1, 97).toString('base64')],
  ];
  for (const [name, data] of bad) {
    const r = await rpc(alice, 'create_document', { p_name: name, p_category: 'Other', p_visibility: 'private', p_editors: [], p_data: data });
    assert.ok(refused(r), `${name} must be rejected`);
  }
  const good = await rpc(alice, 'create_document', { p_name: 'ok.pdf', p_category: 'Other', p_visibility: 'private', p_editors: [], p_data: b64('%PDF-1.4 hi') });
  assert.equal(good.data?.ok, true);
  const rejected = (await audit(alice.id, 'UPLOAD')).filter((x) => x.outcome === 'DENIED');
  assert.ok(rejected.length >= 4, 'rejected uploads are audited');
  const big = await rpc(alice, 'create_document', { p_name: 'three.txt', p_category: 'Other', p_visibility: 'private', p_editors: [], p_data: Buffer.alloc(3 * 1024 * 1024, 97).toString('base64') });
  assert.equal(big.data?.ok, true, 'exactly 3 MB is accepted');
});

test('help desk: the requester cannot answer their own message', async () => {
  const t = await rpc(carol, 'help_create', { p_subject: 'Need access', p_body: 'Please', p_category: 'Access', p_priority: 'normal' });
  assert.equal(t.data?.ok, true);
  assert.ok(refused(await rpc(carol, 'help_reply', { p_ticket: t.data.id, p_body: 'hello?' })));
  assert.equal((await rpc(alice, 'help_reply', { p_ticket: t.data.id, p_body: 'done' })).data?.ok, true);
  assert.equal((await rpc(carol, 'help_reply', { p_ticket: t.data.id, p_body: 'thanks' })).data?.ok, true);
  assert.ok(refused(await rpc(bob, 'help_reply', { p_ticket: t.data.id, p_body: 'let me in' })), 'another owner cannot join');
});

test('a failed sign-in is written to the activity log', async () => {
  const anon = createClient(URL_, ANON, opts);
  const wrong = await anon.auth.signInWithPassword({ email: alice.email, password: 'definitely-wrong' });
  assert.ok(wrong.error);
  await anon.rpc('log_failed_login', { p_email: alice.email, p_reason: 'wrong email or password' });
  const { data } = await svc.from('audit_log').select('detail,outcome,actor').eq('action', 'LOGIN').eq('actor', alice.id).eq('outcome', 'DENIED').order('seq', { ascending: false }).limit(1);
  assert.match(data[0].detail, /failed sign-in for/);
});

test('usernames must be unique', async () => {
  const anon = createClient(URL_, ANON, opts);
  assert.equal((await anon.rpc('username_available', { p_username: `alice_${run}` })).data, false);
  assert.equal((await anon.rpc('username_available', { p_username: `nobody_${run}` })).data, true);
  const dup = await svc.auth.admin.createUser({ email: `dup.${run}@trustvault.test`, password: `Test#${run}9x`, email_confirm: true, user_metadata: { name: 'Dup User', username: `alice_${run}`, role: 'viewer' } });
  assert.ok(dup.error, 'a second account with the same username must fail');
});

test('the admin can verify the audit trail, and only the admin', async () => {
  const ok = await rpc(admin, 'verify_log');
  assert.equal(ok.data?.ok, true, JSON.stringify(ok.data));
  assert.ok(refused(await rpc(bob, 'verify_log')));
  const page = await rpc(admin, 'admin_log', { p_before: null, p_limit: 5, p_outcome: 'DENIED', p_action: null });
  assert.equal(page.data.rows.length, 5);
  assert.ok(page.data.rows.every((r) => r.outcome === 'DENIED'));
  assert.ok(refused(await rpc(bob, 'admin_log', {})));
});

test('owner can delete their document; nobody else can', async () => {
  const mine = await rpc(alice, 'list_documents');
  const target = mine.data.find((d) => d.name === 'ok.pdf');
  assert.ok(refused(await rpc(bob, 'remove_document', { p_id: target.id })));
  assert.equal((await rpc(alice, 'remove_document', { p_id: target.id })).data?.ok, true);
  assert.ok(refused(await rpc(alice, 'inspect_document', { p_id: target.id })));
  assert.ok((await audit(alice.id, 'DELETE', target.id)).some((x) => x.outcome === 'ALLOWED'));
});
