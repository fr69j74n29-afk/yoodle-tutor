-- ════════════════════════════════════════════════════════════════════════════
-- Map view, part 2 (needs 007 for tutor_map_fuzz):
--   • Learners' map shows EVERY live tutor who teaches in person (not just search results).
--     Tutors without a cleared Vulnerable Sector Check are included and flagged (minors_cleared),
--     so the app can mark them when a parent is searching for a child. Booking them for a child
--     is still blocked by tutor_request_booking.
--   • Tutors' map can show learners who OPT IN with "Let tutors near me see I'm looking".
--     Off by default. Learners' areas otherwise stay on their device, as the app promises.
--
-- Privacy rules for learner pins:
--   • Opt-in only, by the learner, and they can switch it off (row deleted) at any time.
--   • Stored point is rounded to ~1 km on save; the map gets tutor_map_fuzz() of it, never the point.
--   • Tutors see first name, "for me" / "for my child", the area label and rough distance. Nothing about
--     the child. Only LIVE tutors can see pins; child pins only reach tutors cleared for under-18s.
--   • Seeing a pin doesn't let a tutor message first. Contact still only starts from a request or the learner.
--   • Pins expire after 90 days unless the learner renews them.
-- Safe to re-run.
-- ════════════════════════════════════════════════════════════════════════════

create table if not exists public.tutor_learner_pins (
  profile_id  uuid primary key references public.profiles(id) on delete cascade,
  for_child   boolean not null default false,
  area_label  text not null check (char_length(area_label) between 1 and 120),
  area_lat    double precision not null,
  area_lng    double precision not null,
  updated_at  timestamptz not null default now(),
  expires_at  timestamptz not null default now() + interval '90 days'
);
alter table public.tutor_learner_pins enable row level security;
-- Learners read their own pin; everything else goes through the functions below.
drop policy if exists tlp_select on public.tutor_learner_pins;
create policy tlp_select on public.tutor_learner_pins for select
  using (profile_id = auth.uid() or public.tutor_is_admin());

-- Learner: switch the pin on (or update / renew it). Coordinates are rounded to ~1 km here.
create or replace function public.tutor_set_learner_pin(
  p_for_child boolean, p_area_label text, p_lat double precision, p_lng double precision)
returns jsonb language plpgsql security definer set search_path = public as $$
begin
  perform public.tutor_assert_active();
  if not exists (select 1 from public.tutor_members where profile_id = auth.uid() and role = 'learner') then
    return jsonb_build_object('ok', false, 'reason', 'not_learner');
  end if;
  if p_lat is null or p_lng is null or coalesce(trim(p_area_label), '') = ''
     or p_lat not between -90 and 90 or p_lng not between -180 and 180 then
    return jsonb_build_object('ok', false, 'reason', 'area_needed');
  end if;
  insert into public.tutor_learner_pins (profile_id, for_child, area_label, area_lat, area_lng, updated_at, expires_at)
  values (auth.uid(), coalesce(p_for_child, false), left(trim(p_area_label), 120),
          round(p_lat::numeric, 2), round(p_lng::numeric, 2), now(), now() + interval '90 days')
  on conflict (profile_id) do update set
    for_child = excluded.for_child, area_label = excluded.area_label,
    area_lat = excluded.area_lat, area_lng = excluded.area_lng,
    updated_at = now(), expires_at = now() + interval '90 days';
  return jsonb_build_object('ok', true);
end $$;

-- Learner: switch the pin off. The row is deleted, nothing is kept.
create or replace function public.tutor_clear_learner_pin()
returns jsonb language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not_signed_in'; end if;
  delete from public.tutor_learner_pins where profile_id = auth.uid();
  return jsonb_build_object('ok', true);
end $$;

-- Learner map: every live in-person tutor near a point (closest first). No filters on purpose;
-- the list view keeps the filtered, ranked search.
create or replace function public.tutor_map_tutors(p_lat double precision, p_lng double precision)
returns table (profile_id uuid, name text, hourly_rate numeric, modes text, service_area text,
               rating numeric, review_count int, minors_cleared boolean,
               map_lat double precision, map_lng double precision)
language sql stable security definer set search_path = public as $$
  select t.profile_id, p.name, t.hourly_rate, t.modes, t.service_area, t.rating, t.review_count,
         public.tutor_minors_ok(t),
         public.tutor_map_fuzz(t.area_lat, t.profile_id, 'lat'),
         public.tutor_map_fuzz(t.area_lng, t.profile_id, 'lng')
  from public.tutor_profiles t join public.profiles p on p.id = t.profile_id
  where auth.uid() is not null
    and public.tutor_is_live(t)
    and t.modes <> 'online' and t.area_lat is not null
    and t.profile_id <> auth.uid()
    and not public.tutor_blocked_between(t.profile_id, auth.uid())
  order by case when p_lat is null then 0 else
    power(t.area_lat - p_lat, 2) + power((t.area_lng - p_lng) * cos(radians(p_lat)), 2) end
  limit 300;
$$;

-- Tutor map: opted-in learners near the tutor's own area (closest first). Live tutors only.
-- Pins for a child are only returned to tutors cleared for under-18s.
create or replace function public.tutor_map_learners()
returns table (learner_id uuid, first_name text, for_child boolean, area_label text, distance_km numeric,
               map_lat double precision, map_lng double precision)
language sql stable security definer set search_path = public as $$
  select l.profile_id, coalesce(nullif(split_part(trim(p.name), ' ', 1), ''), 'A learner'),
         l.for_child, l.area_label,
         case when m.area_lat is null then null else round((6371 * 2 * asin(sqrt(
           power(sin(radians(l.area_lat - m.area_lat) / 2), 2)
           + cos(radians(m.area_lat)) * cos(radians(l.area_lat)) * power(sin(radians(l.area_lng - m.area_lng) / 2), 2))))::numeric, 1) end,
         public.tutor_map_fuzz(l.area_lat, l.profile_id, 'lat'),
         public.tutor_map_fuzz(l.area_lng, l.profile_id, 'lng')
  from public.tutor_profiles m
  join public.tutor_learner_pins l on l.expires_at > now() and l.profile_id <> m.profile_id
  join public.profiles p on p.id = l.profile_id
  where m.profile_id = auth.uid() and public.tutor_is_live(m) and not public.am_i_suspended()
    and not public.tutor_blocked_between(l.profile_id, m.profile_id)
    and (not l.for_child or public.tutor_minors_ok(m))
  order by case when m.area_lat is null then 0 else
    power(l.area_lat - m.area_lat, 2) + power((l.area_lng - m.area_lng) * cos(radians(m.area_lat)), 2) end
  limit 300;
$$;

-- ─── Grants ─────────────────────────────────────────────────────────────────
revoke execute on function
  public.tutor_set_learner_pin(boolean, text, double precision, double precision),
  public.tutor_clear_learner_pin(),
  public.tutor_map_tutors(double precision, double precision),
  public.tutor_map_learners()
from public, anon;
grant execute on function
  public.tutor_set_learner_pin(boolean, text, double precision, double precision),
  public.tutor_clear_learner_pin(),
  public.tutor_map_tutors(double precision, double precision),
  public.tutor_map_learners()
to authenticated;
