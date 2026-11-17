-- ════════════════════════════════════════════════════════════════════════════
-- 011 (15 Nov 2026). Needs 010.
--
-- 1. yoodle.ca helpers with the "Tutoring" tag are no longer shown on the Yoodle Tutors map.
--    They appear only after they join Yoodle Tutors, set up a tutor profile and go live
--    (then they are ordinary tutors, with the same under-18 rules as everyone else).
--    The invite to them from yoodle.ca is NOT sent here.
-- 2. Every new tutor gets a "Finish setting up your profile to go live" notification
--    in their Yoodle Tutors notifications the moment their tutor account is created.
-- Safe to re-run.
-- ════════════════════════════════════════════════════════════════════════════

-- ─── 1. Map: live tutors only (no yoodle.ca helpers) ────────────────────────
-- Same signature and columns as 010, so the app keeps working; source is always 'tutor'.
create or replace function public.tutor_map_tutors(p_lat double precision, p_lng double precision,
                                                   p_for_child boolean default false)
returns table (profile_id uuid, name text, hourly_rate numeric, modes text, service_area text,
               rating numeric, review_count int, minors_cleared boolean,
               map_lat double precision, map_lng double precision,
               id_verified boolean, source text)
language sql stable security definer set search_path = public as $$
  select t.profile_id, p.name, t.hourly_rate, t.modes, t.service_area, t.rating, t.review_count,
         public.tutor_minors_ok(t),
         public.tutor_map_fuzz(t.area_lat, t.profile_id, 'lat'),
         public.tutor_map_fuzz(t.area_lng, t.profile_id, 'lng'),
         public.tutor_id_verified(t.profile_id), 'tutor'::text
  from public.tutor_profiles t join public.profiles p on p.id = t.profile_id
  where auth.uid() is not null
    and public.tutor_is_live(t)
    and t.modes <> 'online' and t.area_lat is not null
    and t.profile_id <> auth.uid()
    and not public.tutor_blocked_between(t.profile_id, auth.uid())
    and (not coalesce(p_for_child, false) or public.tutor_minors_ok(t))
  order by case when p_lat is null then 0 else
    power(t.area_lat - p_lat, 2) + power((t.area_lng - p_lng) * cos(radians(p_lat)), 2) end
  limit 300;
$$;
revoke execute on function public.tutor_map_tutors(double precision, double precision, boolean) from public, anon;
grant execute on function public.tutor_map_tutors(double precision, double precision, boolean) to authenticated;

-- ─── 2. Welcome notification for new tutors ─────────────────────────────────
create or replace function public.tutor_welcome_notice()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.role = 'tutor' and not exists (
       select 1 from public.tutor_notifications where profile_id = new.profile_id and kind = 'setup') then
    insert into public.tutor_notifications (profile_id, kind, title, body, link)
    values (new.profile_id, 'setup', 'Finish setting up your profile to go live',
            'Add your subjects, grade levels, hourly rate and a short bio, then switch your listing on. Learners can find you once you''re live.',
            'profile');
  end if;
  return new;
end $$;
revoke execute on function public.tutor_welcome_notice() from public, anon, authenticated;

drop trigger if exists tutor_members_welcome on public.tutor_members;
create trigger tutor_members_welcome after insert on public.tutor_members
  for each row execute function public.tutor_welcome_notice();
