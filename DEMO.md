# Demo video script (about 6 minutes)

Record the live site. Have two browser profiles ready (owner1 and viewer1) and one for admin.

1. **0:00 Intro (20 s).** What TrustVault is; the three roles; point at the Roles page.
2. **0:20 Owner uploads (60 s).** Sign in as `owner1`. Upload `plan.txt` as *Only people I pick*. Try a fake `.pdf`
   (a text file renamed) and show the server rejection. Upload a ~3 MB file.
3. **1:20 Permission denied (60 s).** Sign in as `owner2` in another profile: the document is not listed; open the
   command palette and show it cannot be found. In the browser console run
   `await sb.rpc('inspect_document', { p_id: 1 })` (use the real id) and show the refusal.
4. **2:20 Grant and revoke (75 s).** As `owner1` grant `owner2` read access. `owner2` opens it. Revoke. `owner2`
   refreshes: gone immediately. Show edit access: grant edit, edit, revoke.
5. **3:35 Audit trail (60 s).** Owner view: the document's trail with ALLOWED and DENIED lines.
   Admin: Administration → Activity, filter Result = Refused, then Action = PERMISSION_GRANT. Show a failed sign-in line
   (enter a wrong password first).
6. **4:35 Admin limits and integrity (45 s).** Admin cannot open document contents (register only). Integrity → Verify now.
7. **5:20 Tests (40 s).** Terminal: `npm run test:db` (all PASS) and `npm test`.
8. **6:00 Close.** Link to THREATS.md and the repo.
