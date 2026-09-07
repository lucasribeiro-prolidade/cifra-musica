-- Cifra-Musica — banco de cifras por usuário
-- Execute este arquivo no Supabase > SQL Editor > New query > Run.

create extension if not exists pgcrypto;

create table if not exists public.cifras (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null default 'Sem título',
  tone text,
  text text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists cifras_user_id_idx on public.cifras(user_id);
create index if not exists cifras_user_updated_idx on public.cifras(user_id, updated_at desc);

alter table public.cifras enable row level security;

-- Recria as políticas para tornar o script seguro de executar novamente.
drop policy if exists "cifras_select_own" on public.cifras;
drop policy if exists "cifras_insert_own" on public.cifras;
drop policy if exists "cifras_update_own" on public.cifras;
drop policy if exists "cifras_delete_own" on public.cifras;

create policy "cifras_select_own"
on public.cifras for select
to authenticated
using (auth.uid() = user_id);

create policy "cifras_insert_own"
on public.cifras for insert
to authenticated
with check (auth.uid() = user_id);

create policy "cifras_update_own"
on public.cifras for update
to authenticated
using (auth.uid() = user_id)
with check (auth.uid() = user_id);

create policy "cifras_delete_own"
on public.cifras for delete
to authenticated
using (auth.uid() = user_id);

-- Mantém updated_at atualizado automaticamente.
create or replace function public.set_cifras_updated_at()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists trg_cifras_updated_at on public.cifras;
create trigger trg_cifras_updated_at
before update on public.cifras
for each row execute function public.set_cifras_updated_at();

grant select, insert, update, delete on public.cifras to authenticated;
