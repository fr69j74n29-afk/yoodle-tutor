-- ════════════════════════════════════════════════════════════════════════════
-- 012 (17 Nov 2026): one account can be a learner AND a tutor.
--
-- Before: tutor_members.role was fixed at onboarding ('learner' or 'tutor') and decided what you could do.
-- Now the two sides are separate:
--   • Tutor side   = you have a tutor_profiles row (unchanged; every tutor RPC already keys off it).
--   • Learner side = tutor_members.learner_at is set (new column). Booking, posting a request and the
--                    learner map pin now check this instead of role = 'learner'.
--   • role         = the side the app is SHOWING (the toggle on the Profile page), remembered across
--                    devices. It no longer grants anything on its own.
-- tutor_use_side() turns a side on (creating the tutor profile if needed) and switches to it.
-- Also: nobody can book themselves now that one account can be on both sides.
--
-- Safe for the app version that's live before this one: existing learners are backfilled, a new
-- 'learner' onboarding row gets learner_at from the trigger, and tutors keep working as before.
-- ════════════════════════════════════════════════════════════════════════════

-- 1. Learner side flag
alter table public.tutor_members add column if not exists learner_at timestamptz;
update public.tutor_members set learner_at = created_at where role = 'learner' and learner_at is null;

create or replace function public.tutor_members_learner_at()
returns trigger language plpgsql set search_path = public as $$
begin
  if new.role = 'learner' and new.learner_at is null then new.learner_at := now(); end if;
  return new;
end $$;
drop trigger if exists tutor_members_learner_at on public.tutor_members;
create trigger tutor_members_learner_at before insert on public.tutor_members
  for each row execute function public.tutor_members_learner_at();

-- 2. Is the caller set up as a learner?
create or replace function public.tutor_is_learner(p_uid uuid default auth.uid())
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.tutor_members where profile_id = p_uid and learner_at is not null);
$$;
revoke all on function public.tutor_is_learner(uuid) from public, anon;
grant execute on function public.tutor_is_learner(uuid) to authenticated;

-- 3. Turn a side on (if needed) and switch the app to it
create or replace function public.tutor_use_side(p_side text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare m public.tutor_members; added boolean := false;
begin
  perform public.tutor_assert_active();
  if p_side not in ('learner', 'tutor') then return jsonb_build_object('ok', false, 'reason', 'side'); end if;
  select * into m from public.tutor_members where profile_id = auth.uid();
  if m is null then return jsonb_build_object('ok', false, 'reason', 'not_member'); end if;

  if p_side = 'learner' and m.learner_at is null then
    update public.tutor_members set learner_at = now() where profile_id = auth.uid();
    added := true;
  elsif p_side = 'tutor' and not exists (select 1 from public.tutor_profiles where profile_id = auth.uid()) then
    insert into public.tutor_profiles (profile_id) values (auth.uid());
    insert into public.tutor_notifications (profile_id, kind, title, body, link)
    select auth.uid(), 'setup', 'Finish setting up your profile to go live',
           'Add your subjects, grade levels, hourly rate and a short bio, then switch your listing on. Learners can find you once you''re live.',
           'profile'
    where not exists (select 1 from public.tutor_notifications where profile_id = auth.uid() and kind = 'setup');
    added := true;
  end if;

  update public.tutor_members set role = p_side where profile_id = auth.uid();
  return jsonb_build_object('ok', true, 'side', p_side, 'added', added);
end $$;
revoke all on function public.tutor_use_side(text) from public, anon;
grant execute on function public.tutor_use_side(text) to authenticated;

-- 4. Learner actions check the learner side, not role
do $$
declare fn text; def text;
begin
  foreach fn in array array['tutor_request_booking', 'tutor_post_request', 'tutor_set_learner_pin'] loop
    select pg_get_functiondef(p.oid) into def
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public' and p.proname = fn;
    if def is null then raise exception '012: function % not found', fn; end if;
    if position('role = ''learner''' in def) = 0 then raise exception '012: % has no role check to replace', fn; end if;
    def := replace(def,
      'if not exists (select 1 from public.tutor_members where profile_id = auth.uid() and role = ''learner'') then',
      'if not public.tutor_is_learner() then');
    if position('role = ''learner''' in def) > 0 then raise exception '012: % role check not replaced', fn; end if;
    -- 5. No booking yourself
    if fn = 'tutor_request_booking' then
      def := replace(def,
        'if not coalesce(p_safety_ack, false) then',
        'if p_tutor = auth.uid() then return jsonb_build_object(''ok'', false, ''reason'', ''self_booking''); end if;' || chr(10) ||
        '  if not coalesce(p_safety_ack, false) then');
      if position('self_booking' in def) = 0 then raise exception '012: self-booking guard not added'; end if;
    end if;
    execute def;
  end loop;
end $$;
