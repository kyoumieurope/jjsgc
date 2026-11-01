-- Run this once in Supabase → SQL Editor.
create table public.profiles(
  user_id uuid primary key references auth.users(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 24),
  roblox text not null check (roblox ~ '^[A-Za-z0-9_]{3,20}$'),
  region text not null check (region in ('NA','EU','AS')),
  grade text not null default 'G1' check (grade in ('G1','SG1','SG')),
  sub text not null default 'Weak' check (sub in ('Weak','Low','Stable','Mid','Strong','High')),
  created_at timestamptz not null default now()
);
create unique index profiles_roblox_unique on public.profiles(lower(roblox));

create table public.admins(user_id uuid primary key references auth.users(id) on delete cascade);
alter table public.admins enable row level security; -- no policies: clients can't touch it

create function public.is_admin() returns boolean language sql security definer stable set search_path=public as
$$ select exists(select 1 from public.admins where user_id=auth.uid()) $$;

alter table public.profiles enable row level security;
create policy "anyone reads" on public.profiles for select using (true);
create policy "insert own" on public.profiles for insert to authenticated with check (auth.uid()=user_id);
create policy "update own or admin" on public.profiles for update to authenticated using (auth.uid()=user_id or public.is_admin());
create policy "delete own or admin" on public.profiles for delete to authenticated using (auth.uid()=user_id or public.is_admin());

-- Players can never set grade/sub themselves; only admins via set_grade().
revoke all on public.profiles from anon, authenticated;
grant select on public.profiles to anon, authenticated;
grant insert (user_id,name,roblox,region) on public.profiles to authenticated;
grant update (name,roblox,region) on public.profiles to authenticated;
grant delete on public.profiles to authenticated;

create function public.set_grade(target uuid,g text,s text) returns void language plpgsql security definer set search_path=public as
$$ begin
  if not public.is_admin() then raise exception 'not allowed'; end if;
  update public.profiles set grade=g, sub=s where user_id=target;
end $$;
revoke execute on function public.set_grade(uuid,text,text) from public, anon;
grant execute on function public.set_grade(uuid,text,text) to authenticated;

alter publication supabase_realtime add table public.profiles;
