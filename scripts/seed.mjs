// Creates one demo account per role (and two sample documents). Safe to run again.
//   cp .env.example .env   (fill it in)   then   node --env-file=.env scripts/seed.mjs
import { createClient } from '@supabase/supabase-js';

const { SUPABASE_URL: url, SUPABASE_ANON_KEY: anon, SUPABASE_SERVICE_ROLE_KEY: service } = process.env;
if (!url || !anon || !service) { console.error('Set SUPABASE_URL, SUPABASE_ANON_KEY and SUPABASE_SERVICE_ROLE_KEY (see .env.example).'); process.exit(1); }
const password = process.env.SEED_PASSWORD || 'TrustVault#2026';
const opts = { auth: { persistSession: false, autoRefreshToken: false } };
const svc = createClient(url, service, opts);

const people = [
  { email: 'admin@trustvault.test',   name: 'Ada Admin',     username: 'ada.admin',     role: 'admin' },
  { email: 'owner1@trustvault.test',  name: 'Olivia Owner',  username: 'olivia.owner',  role: 'owner' },
  { email: 'owner2@trustvault.test',  name: 'Omar Owner',    username: 'omar.owner',    role: 'owner' },
  { email: 'viewer1@trustvault.test', name: 'Vera Viewer',   username: 'vera.viewer',   role: 'viewer', boss: 'owner1@trustvault.test' },
  { email: 'viewer2@trustvault.test', name: 'Victor Viewer', username: 'victor.viewer', role: 'viewer', boss: 'owner2@trustvault.test' },
];

const ids = {};
for (const p of people) {
  const { data, error } = await svc.auth.admin.createUser({
    email: p.email, password, email_confirm: true,
    user_metadata: { name: p.name, username: p.username, role: p.role === 'admin' ? 'viewer' : p.role },
  });
  if (error && !/already|registered|exists/i.test(error.message)) throw error;
  if (data?.user) ids[p.email] = data.user.id;
  else {
    const { data: row, error: e2 } = await svc.from('profiles').select('id').eq('email', p.email).single();
    if (e2) throw e2;
    ids[p.email] = row.id;
  }
}
for (const p of people) {
  const { error } = await svc.from('profiles')
    .update({ role: p.role, approved: true, active: true, owner_id: p.boss ? ids[p.boss] : null }).eq('id', ids[p.email]);
  if (error) throw error;
}

// two sample documents for the first owner (through the real API, so they are audited)
const o1 = createClient(url, anon, opts);
const { error: se } = await o1.auth.signInWithPassword({ email: 'owner1@trustvault.test', password });
if (se) throw se;
const { data: mine } = await o1.rpc('list_documents', {});
const have = new Set((Array.isArray(mine) ? mine : []).map((d) => d.name));
const b64 = (t) => Buffer.from(t).toString('base64');
for (const [name, cat, vis, text] of [
  ['welcome.txt', 'Other', 'everyone', 'Welcome to TrustVault. Everyone can read this one.'],
  ['salaries.csv', 'HR', 'private', 'name,salary\nAda,100\nOlivia,120\n'],
]) {
  if (have.has(name)) continue;
  const { data, error } = await o1.rpc('create_document', { p_name: name, p_category: cat, p_visibility: vis, p_editors: [], p_data: b64(text) });
  if (error || data?.ok === false) console.warn('sample document skipped:', name, error?.message || data?.message);
}

console.log('\nSeed accounts (password for all: ' + password + ')');
for (const p of people) console.log(`  ${p.role.padEnd(7)} ${p.email}`);
console.log('\nSign in at your site with any of them. Change or delete these before real use.');
