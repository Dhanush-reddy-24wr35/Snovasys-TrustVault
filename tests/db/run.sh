#!/usr/bin/env bash
# Runs the database tests against a THROWAWAY local Postgres database (never your Supabase project).
# Usage: PGHOST=... PGPORT=... PGUSER=postgres ./tests/db/run.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
DB=tv_test_$$
createdb "$DB"; trap 'dropdb --if-exists "$DB"' EXIT
P="psql -d $DB -q -v ON_ERROR_STOP=1"
$P -f tests/db/stubs.sql   # roles, auth.* and storage.* stand-ins for Supabase
$P -f sql/01_schema.sql 2>&1 | grep -v NOTICE || true
$P -f sql/02_help_desk.sql
$P -f sql/03_hardening.sql 2>&1 | grep -v NOTICE || true
out=$(psql -d "$DB" -q -f tests/db/hardening_test.sql 2>&1 | grep -v NOTICE)
echo "$out"
if echo "$out" | grep -qE '^ FAIL|ERROR'; then echo 'DATABASE TESTS FAILED'; exit 3; fi
echo 'DATABASE TESTS PASSED'
