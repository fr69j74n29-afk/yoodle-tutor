-- ════════════════════════════════════════════════════════════════════════════
-- 010 (15 Nov 2026): open listing + yoodle.ca tutoring helpers on the map. Needs 007 and 008.
--
-- 1. Going live no longer needs a paid Stripe ID check or an admin approval.
--    A tutor is live when their listing is switched on and their profile is complete
--    (subjects, grades, rate, bio). Yoodle can still take a tutor down: admin_hidden,
--    a rejected review, or a yoodle.ca suspension.
--    The ONE hard rule stays: no cleared Vulnerable Sector Check → no under-18 students
--    (tutor_minors_ok is unchanged and still enforced by search, booking and acceptance).
-- 2. ID verification becomes an optional badge. tutor_search, tutor_map_tutors and
--    tutor_public_profile now return the real id_verified value instead of assuming it.
-- 3. tutor_map_tutors also returns yoodle.ca helpers who picked the "Tutoring" category and
--    are visible on the yoodle.ca map, but have no live tutor profile yet (source = 'yoodle').
--    They are never cleared for under-18s, can't be booked here, and their pin uses the same
--    ~1 km fuzz as tutors (from profiles.last_lat/last_lng; the street address is never returned).
-- 4. tutor_me returns 'live', so the app shows the same rule the database applies.
-- Safe to re-run.
-- ════════════════════════════════════════════════════════════════════════════

-- ─── 1. Live rule ───────────────────────────────────────────────────────────
create or replace function public.tutor_is_live(tp tutor_profiles)
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce(tp.listed, false)
     and not coalesce(tp.admin_hidden, false)
     and coalesce(tp.review_status, 'draft') <> 'rejected'
     and coalesce(cardinality(tp.subjects), 0) > 0
     and coalesce(cardinality(tp.grade_levels), 0) > 0
     and tp.hourly_rate is not null
     and coalesce(trim(tp.bio), '') <> ''
     and not exists (select 1 from public.suspended_users s where s.user_id = tp.profile_id);
$$;

-- ─── 4. tutor_me: + live ────────────────────────────────────────────────────
create or replace function public.tutor_me()
returns jsonb language sql stable security definer set search_path = public as $$
  select jsonb_build_object(
    'member', (select to_jsonb(m) from public.tutor_members m where m.profile_id = auth.uid()),
    'tutor', (select to_jsonb(t) - 'area_lat' - 'area_lng' from public.tutor_profiles t where t.profile_id = auth.uid()),
    'live', coalesce((select public.tutor_is_live(t) from public.tutor_profiles t where t.profile_id = auth.uid()), false),
    'id_verified', public.tutor_id_verified(auth.uid()),
    'suspended', public.am_i_suspended());
$$;

-- ─── 2. tutor_search: + id_verified (return type changes → drop + create) ──
drop function if exists public.tutor_search(double precision, double precision, text, text, int, numeric, text, text, text, boolean, int);
create function public.tutor_search(
  p_lat double precision, p_lng double precision,
  p_subject text default null, p_grade text default null,
  p_max_km int default 25, p_max_rate numeric default null,
  p_mode text default null, p_day text default null, p_time text default null,
  p_for_child boolean default false, p_limit int default 60)
returns table (
  profile_id uuid, name text, headline text, subjects text[], grade_levels text[],
  hourly_rate numeric, modes text, service_area text, distance_km numeric,
  rating numeric, review_count int, repeat_learners int, minors_cleared boolean,
  match_score numeric, map_lat double precision, map_lng double precision, id_verified boolean)
language sql stable security definer set search_path = public as $$
  with base as (
    select t.*, p.name as pname, public.tutor_minors_ok(t) as minors_ok,
      case when p_lat is null or t.area_lat is null then null else
        6371 * 2 * asin(sqrt(power(sin(radians(t.area_lat - p_lat) / 2), 2)
          + cos(radians(p_lat)) * cos(radians(t.area_lat)) * power(sin(radians(t.area_lng - p_lng) / 2), 2)))
      end as dist
    from public.tutor_profiles t join public.profiles p on p.id = t.profile_id
    where public.tutor_is_live(t)
      and t.profile_id <> coalesce(auth.uid(), '00000000-0000-0000-0000-000000000000')
      and not public.tutor_blocked_between(t.profile_id, auth.uid())
      and (p_subject is null or p_subject = any(t.subjects))
      and (p_grade is null or p_grade = any(t.grade_levels))
      and (p_max_rate is null or t.hourly_rate <= p_max_rate)
      and (not p_for_child or public.tutor_minors_ok(t))
  ), filtered as (
    select b.*,
      (b.modes in ('in_person', 'both') and b.dist is not null
        and b.dist <= least(coalesce(p_max_km, 25), b.travel_km)) as can_in_person,
      (b.modes in ('online', 'both')) as can_online,
      (p_day is null or (b.availability ? p_day and
        (p_time is null or b.availability -> p_day ? p_time))) as avail_ok
    from base b
  )
  select f.profile_id, f.pname, f.headline, f.subjects, f.grade_levels, f.hourly_rate, f.modes,
         f.service_area, round(f.dist::numeric, 1), f.rating, f.review_count,
         public.tutor_repeat_learners(f.profile_id), f.minors_ok,
         round((
           coalesce(f.rating, 4.0) / 5 * 30 * least(1, (f.review_count + 1) / 4.0)
           + case when f.can_in_person then 30 * (1 - f.dist / greatest(coalesce(p_max_km, 25), 1)) else 12 end
           + case when p_grade is not null then 10 else 0 end
           + case when f.avail_ok and p_day is not null then 15 else 0 end
           + 10 * least(public.tutor_repeat_learners(f.profile_id), 5) / 5.0
         )::numeric, 1) as score,
         case when f.modes <> 'online' then public.tutor_map_fuzz(f.area_lat, f.profile_id, 'lat') end,
         case when f.modes <> 'online' then public.tutor_map_fuzz(f.area_lng, f.profile_id, 'lng') end,
         public.tutor_id_verified(f.profile_id)
  from filtered f
  where f.avail_ok
    and case coalesce(p_mode, '')
          when 'in_person' then f.can_in_person
          when 'online' then f.can_online
          else f.can_in_person or f.can_online end
  order by score desc, f.dist nulls last
  limit least(coalesce(p_limit, 60), 100);
$$;

-- ─── 2+3. tutor_map_tutors: + id_verified, source, yoodle.ca tutoring helpers ──
-- p_for_child = true (parent looking for their child) → only tutors with a cleared Vulnerable
-- Sector Check, and no yoodle.ca helpers (never cleared). Same rule as tutor_search.
drop function if exists public.tutor_map_tutors(double precision, double precision);
drop function if exists public.tutor_map_tutors(double precision, double precision, boolean);
create function public.tutor_map_tutors(p_lat double precision, p_lng double precision,
                                        p_for_child boolean default false)
returns table (profile_id uuid, name text, hourly_rate numeric, modes text, service_area text,
               rating numeric, review_count int, minors_cleared boolean,
               map_lat double precision, map_lng double precision,
               id_verified boolean, source text)
language sql stable security definer set search_path = public as $$
  select profile_id, name, hourly_rate, modes, service_area, rating, review_count, minors_cleared,
         map_lat, map_lng, id_verified, source
  from (
    -- live tutors who teach in person (as in 008)
    select t.profile_id, p.name, t.hourly_rate, t.modes, t.service_area, t.rating, t.review_count,
           public.tutor_minors_ok(t) as minors_cleared,
           public.tutor_map_fuzz(t.area_lat, t.profile_id, 'lat') as map_lat,
           public.tutor_map_fuzz(t.area_lng, t.profile_id, 'lng') as map_lng,
           public.tutor_id_verified(t.profile_id) as id_verified, 'tutor'::text as source,
           t.area_lat as s_lat, t.area_lng as s_lng
    from public.tutor_profiles t join public.profiles p on p.id = t.profile_id
    where public.tutor_is_live(t)
      and t.modes <> 'online' and t.area_lat is not null
      and t.profile_id <> auth.uid()
      and not public.tutor_blocked_between(t.profile_id, auth.uid())
      and (not coalesce(p_for_child, false) or public.tutor_minors_ok(t))
    union all
    -- yoodle.ca helpers with the Tutoring category, on the yoodle.ca map, no live tutor profile
    select p.id, p.name,
           case when p.helper_rate_type = 'hourly' then p.helper_rate end,
           'in_person', nullif(trim(coalesce(p.place_city, '')), ''),
           p.rating, 0, false,
           public.tutor_map_fuzz(p.last_lat, p.id, 'lat'),
           public.tutor_map_fuzz(p.last_lng, p.id, 'lng'),
           public.tutor_id_verified(p.id), 'yoodle',
           p.last_lat, p.last_lng
    from public.profiles p
    where not coalesce(p_for_child, false)
      and 'Tutoring' = any(p.helper_categories)
      and p.visible_on_map and coalesce(p.show_on_map, true)
      and p.last_lat is not null and p.last_lng is not null
      and p.id <> auth.uid()
      and (not coalesce(p.is_tester, false) or public.is_tester(auth.uid()))
      and not coalesce(p.is_demo, false)
      and not exists (select 1 from public.suspended_users s where s.user_id = p.id)
      and not exists (select 1 from public.tutor_profiles t where t.profile_id = p.id and public.tutor_is_live(t))
      and not public.tutor_blocked_between(p.id, auth.uid())
  ) x
  where auth.uid() is not null
  order by case when p_lat is null then 0 else
    power(x.s_lat - p_lat, 2) + power((x.s_lng - p_lng) * cos(radians(p_lat)), 2) end
  limit 300;
$$;

-- ─── 2. tutor_public_profile: real id_verified ──────────────────────────────
create or replace function public.tutor_public_profile(p_tutor uuid)
returns jsonb language sql stable security definer set search_path = public as $$
  select case when t is null or not public.tutor_is_live(t)
                   or public.tutor_blocked_between(t.profile_id, auth.uid()) then null
  else jsonb_build_object(
    'profile_id', t.profile_id, 'name', p.name, 'headline', t.headline, 'bio', t.bio,
    'subjects', t.subjects, 'grade_levels', t.grade_levels, 'hourly_rate', t.hourly_rate,
    'modes', t.modes, 'service_area', t.service_area, 'travel_km', t.travel_km,
    'availability', t.availability, 'rating', t.rating, 'review_count', t.review_count,
    'repeat_learners', public.tutor_repeat_learners(t.profile_id),
    'id_verified', public.tutor_id_verified(t.profile_id), 'minors_cleared', public.tutor_minors_ok(t),
    'reviews', coalesce((select jsonb_agg(jsonb_build_object(
        'rating', r.rating, 'body', r.body, 'created_at', r.created_at,
        'reviewer', split_part(coalesce(rp.name, 'Learner'), ' ', 1)) order by r.created_at desc)
      from (select * from public.tutor_reviews where tutor_id = t.profile_id and not hidden
            order by created_at desc limit 20) r
      left join public.profiles rp on rp.id = r.reviewer_id), '[]'::jsonb))
  end
  from public.tutor_profiles t join public.profiles p on p.id = t.profile_id
  where t.profile_id = p_tutor;
$$;

-- ─── Grants ─────────────────────────────────────────────────────────────────
revoke execute on function
  public.tutor_search(double precision, double precision, text, text, int, numeric, text, text, text, boolean, int),
  public.tutor_map_tutors(double precision, double precision, boolean)
from public, anon;
grant execute on function
  public.tutor_search(double precision, double precision, text, text, int, numeric, text, text, text, boolean, int),
  public.tutor_map_tutors(double precision, double precision, boolean)
to authenticated;
