-- ════════════════════════════════════════════════════════════════════════════
-- 015 (18 Nov 2026): the "This is for a minor" setting is enforced by the database, not just the app.
--
-- 013 made for_minor an account setting, but the app still sent for_child itself on pins, requests and
-- bookings. A stale tab (or an old app version) could send for_child = false for a minor account, e.g.
-- moving a child's map pin and turning it into an adult pin that uncleared tutors can see.
-- Now, for an account with for_minor = true:
--   • tutor_learner_pins and tutor_requests rows are always saved with for_child = true.
--   • tutor_bookings rows are always saved with for_child = true, and a booking with a tutor who isn't
--     cleared for under-18s is refused (not_cleared_for_minors).
-- Accounts with for_minor = false are unchanged: they can still send for_child = true themselves.
--
-- Also: backfill for_minor for learners who already had a for-child pin or open request (013 didn't).
-- ════════════════════════════════════════════════════════════════════════════

-- 1. Backfill (safe to re-run)
update public.tutor_members m set for_minor = true
 where not m.for_minor
   and (exists (select 1 from public.tutor_learner_pins l where l.profile_id = m.profile_id and l.for_child)
        or exists (select 1 from public.tutor_requests r where r.learner_id = m.profile_id and r.for_child
                   and r.status = 'open' and r.expires_at > now()));

-- 2. Is this account set as for a minor?
create or replace function public.tutor_account_for_minor(p_uid uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((select for_minor from public.tutor_members where profile_id = p_uid), false);
$$;
revoke all on function public.tutor_account_for_minor(uuid) from public, anon, authenticated;

-- 3. Pins and requests: force for_child
create or replace function public.tutor_force_for_child()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if public.tutor_account_for_minor(case tg_table_name when 'tutor_learner_pins' then new.profile_id
                                                       else new.learner_id end) then
    new.for_child := true;
  end if;
  return new;
end $$;

drop trigger if exists tutor_learner_pins_for_minor on public.tutor_learner_pins;
create trigger tutor_learner_pins_for_minor before insert or update on public.tutor_learner_pins
  for each row execute function public.tutor_force_for_child();
drop trigger if exists tutor_requests_for_minor on public.tutor_requests;
create trigger tutor_requests_for_minor before insert or update on public.tutor_requests
  for each row execute function public.tutor_force_for_child();

-- 4. Bookings: force for_child, and refuse a tutor who isn't cleared
create or replace function public.tutor_bookings_for_minor()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if public.tutor_account_for_minor(new.learner_id) and not new.for_child then
    new.for_child := true;
    if not exists (select 1 from public.tutor_profiles t where t.profile_id = new.tutor_id and public.tutor_minors_ok(t)) then
      raise exception 'not_cleared_for_minors';
    end if;
  end if;
  return new;
end $$;
drop trigger if exists tutor_bookings_for_minor on public.tutor_bookings;
create trigger tutor_bookings_for_minor before insert on public.tutor_bookings
  for each row execute function public.tutor_bookings_for_minor();
