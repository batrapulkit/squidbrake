-- Squidbrake Console sign-ups, in Supabase. Run once: Supabase > SQL Editor > New query > paste > Run.
--
-- Everyone who asks for a sign-in link on console.squidbrake.com becomes a row here, with what they typed
-- (name, company, agents). confirmed_at fills in when they click the link, so the rows without it are the people
-- who started and never finished: your follow-up list. See them in Table Editor > profiles.
--
-- Nobody using the public (anon) key can read or change this table; only you, in the Supabase dashboard.
-- The setup links and pilot codes stay on pilots.squidbrake.com (admin page); this is the list of people.

create table if not exists public.profiles (
  id            uuid primary key references auth.users (id) on delete cascade,
  email         text not null,
  name          text check (char_length(name) <= 120),
  company       text check (char_length(company) <= 160),
  agents        text[] not null default '{}',
  created_at    timestamptz not null default now(),
  confirmed_at  timestamptz
);

create index if not exists profiles_created_at on public.profiles (created_at desc);

alter table public.profiles enable row level security;
revoke all on public.profiles from anon, authenticated;

-- A new sign-in user: copy what the form sent (kept on the user as metadata) into profiles.
create or replace function public.squidbrake_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, email, name, company, agents, confirmed_at)
  values (
    new.id,
    lower(new.email),
    left(new.raw_user_meta_data ->> 'name', 120),
    left(new.raw_user_meta_data ->> 'company', 160),
    coalesce(
      array(select left(a, 30) from jsonb_array_elements_text(
              case when jsonb_typeof(new.raw_user_meta_data -> 'agents') = 'array'
                   then new.raw_user_meta_data -> 'agents' else '[]'::jsonb end) as a limit 12),
      '{}'),
    new.email_confirmed_at
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

-- They clicked the link: mark it.
create or replace function public.squidbrake_user_confirmed()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  update public.profiles set confirmed_at = new.email_confirmed_at, email = lower(new.email) where id = new.id;
  return new;
end;
$$;

drop trigger if exists squidbrake_on_signup on auth.users;
create trigger squidbrake_on_signup
  after insert on auth.users
  for each row execute function public.squidbrake_new_user();

drop trigger if exists squidbrake_on_confirm on auth.users;
create trigger squidbrake_on_confirm
  after update of email_confirmed_at, email on auth.users
  for each row when (new.email_confirmed_at is distinct from old.email_confirmed_at or new.email is distinct from old.email)
  execute function public.squidbrake_user_confirmed();

-- Anyone who signed up before you ran this file.
insert into public.profiles (id, email, name, company, agents, created_at, confirmed_at)
select u.id, lower(u.email), left(u.raw_user_meta_data ->> 'name', 120), left(u.raw_user_meta_data ->> 'company', 160),
       coalesce(array(select left(a, 30) from jsonb_array_elements_text(
         case when jsonb_typeof(u.raw_user_meta_data -> 'agents') = 'array' then u.raw_user_meta_data -> 'agents'
              else '[]'::jsonb end) as a limit 12), '{}'),
       u.created_at, u.email_confirmed_at
from auth.users u
on conflict (id) do nothing;
