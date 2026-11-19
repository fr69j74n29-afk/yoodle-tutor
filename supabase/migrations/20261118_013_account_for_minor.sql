-- ════════════════════════════════════════════════════════════════════════════
-- 013 (18 Nov 2026): "This account is for a minor" is one account setting.
--
-- Before: learners picked "For me" / "For my child" on the Find screen, the booking form, the request
-- form and the map pin, each on its own.
-- Now: tutor_members.for_minor is set once (at setup, or with the toggle on the Profile page).
--   • On  → the app only shows tutors with a cleared Vulnerable Sector Check (search and map), and every
--           booking, request and map pin is sent as for_child = true.
--   • Off → the app shows every live tutor, as before.
-- The database rules don't change: tutor_minors_ok() is still enforced by search, booking and acceptance.
-- Turning the setting on or off also updates an active learner map pin, so it matches straight away.
--
-- Safe for the app version that's live before this one: the column has a default and nothing reads it yet.
-- ════════════════════════════════════════════════════════════════════════════

alter table public.tutor_members add column if not exists for_minor boolean not null default false;

create or replace function public.tutor_set_for_minor(p_on boolean)
returns jsonb language plpgsql security definer set search_path = public as $$
begin
  perform public.tutor_assert_active();
  update public.tutor_members set for_minor = coalesce(p_on, false) where profile_id = auth.uid();
  if not found then return jsonb_build_object('ok', false, 'reason', 'not_member'); end if;
  update public.tutor_learner_pins set for_child = coalesce(p_on, false), updated_at = now()
   where profile_id = auth.uid();
  return jsonb_build_object('ok', true, 'for_minor', coalesce(p_on, false));
end $$;
revoke all on function public.tutor_set_for_minor(boolean) from public, anon;
grant execute on function public.tutor_set_for_minor(boolean) to authenticated;
