-- Every Yoodle Tutors account must have a password (added 2026-11-14).
-- Accounts created with an email code or Google have none, so after sign-in the app asks
-- tutor_has_password() and, if false, shows a set-password screen that can't be skipped.
-- Returns only a yes/no about the CALLER's own account; the hash itself never leaves the database.
create or replace function public.tutor_has_password()
returns boolean language sql stable security definer set search_path = public, auth as $$
  select coalesce((select u.encrypted_password is not null and u.encrypted_password <> ''
                   from auth.users u where u.id = auth.uid()), false);
$$;
revoke execute on function public.tutor_has_password() from public, anon;
grant execute on function public.tutor_has_password() to authenticated;
