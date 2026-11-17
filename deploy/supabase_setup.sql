-- Squidbrake's gateway on Supabase: run in the SQL editor. Safe to run again (and do: once before the first start,
-- once after it, so the tables the gateway made on its first start get the same treatment).
-- Use a Supabase project of its own for the gateway: it holds what your agents did (redacted, see README "What is stored").
-- Placeholders in angle brackets. Never commit the real password.

-- 1. The gateway's own schema (start the gateway with DB_SCHEMA=squidbrake). Supabase's REST API doesn't serve a
--    schema unless you add it under Settings > API > Exposed schemas: don't.
create schema if not exists squidbrake;

-- 2. A login for the gateway that isn't the postgres superuser. It owns the tables it creates, and nothing else.
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'squidbrake_gateway') then
    create role squidbrake_gateway login password '<A-LONG-RANDOM-PASSWORD>';
  end if;
end $$;
grant usage, create on schema squidbrake to squidbrake_gateway;

-- 3. The REST API's roles get nothing: not the schema, its tables or its sequences. (Supabase's automatic grants to
--    anon cover what postgres creates in public; tables squidbrake_gateway creates get none, and this re-checks.)
revoke all on schema squidbrake from anon, authenticated, public;
revoke all on all tables in schema squidbrake from anon, authenticated, public;
revoke all on all sequences in schema squidbrake from anon, authenticated, public;

-- 4. Row level security on, with no policies: anyone but the tables' owner (the gateway) reads and writes nothing.
--    Also on the gateway's tables in public, for a gateway started without DB_SCHEMA.
do $$
declare t record;
begin
  for t in
    select schemaname, tablename from pg_tables
    where schemaname = 'squidbrake'
       or (schemaname = 'public' and tablename in ('events', 'notes', 'gateway_state', 'audit_log', 'audit_checkpoints',
                                                   'snapshots', 'usage', 'devices', 'capabilities', 'policy_versions'))
  loop
    execute format('alter table %I.%I enable row level security', t.schemaname, t.tablename);
    execute format('revoke all on table %I.%I from anon, authenticated', t.schemaname, t.tablename);
  end loop;
end $$;

-- 5. Check: every row should say true.
select schemaname, tablename, rowsecurity from pg_tables
where schemaname = 'squidbrake'
   or (schemaname = 'public' and tablename in ('events', 'audit_log', 'capabilities'));
