-- Map view for Find (tutors) and Learners (requests).
-- tutor_search() and tutor_browse_requests() now also return map_lat / map_lng: an APPROXIMATE
-- spot for the pin, never the stored coordinates. The stored point is snapped to a 0.01° grid
-- (~1.1 km) and then moved by a fixed offset of up to ±0.004° that is derived from the person's id.
-- Because the offset is per person (not per request or per page load), the same person always gets the
-- same pin, so repeat requests or refreshing the map can't be averaged back to their real location.
-- Nothing else about either function changes. The return type changes, so both are dropped and re-created.

create or replace function public.tutor_map_fuzz(p_coord double precision, p_person uuid, p_salt text)
returns double precision language sql immutable set search_path = public as $$
  select case when p_coord is null then null else
    round(p_coord::numeric, 2)::double precision
    + ((('x' || substr(md5(p_person::text || p_salt), 1, 6))::bit(24)::int / 16777215.0) - 0.5) * 0.008
  end;
$$;
revoke execute on function public.tutor_map_fuzz(double precision, uuid, text) from public, anon, authenticated;

-- ─── tutor_search ───────────────────────────────────────────────────────────
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
  match_score numeric, map_lat double precision, map_lng double precision)
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
           coalesce(f.rating, 4.0) / 5 * 30 * least(1, (f.review_count + 1) / 4.0)   -- rating, trusted more with reviews
           + case when f.can_in_person then 30 * (1 - f.dist / greatest(coalesce(p_max_km, 25), 1)) else 12 end
           + case when p_grade is not null then 10 else 0 end
           + case when f.avail_ok and p_day is not null then 15 else 0 end
           + 10 * least(public.tutor_repeat_learners(f.profile_id), 5) / 5.0
         )::numeric, 1) as score,
         case when f.modes <> 'online' then public.tutor_map_fuzz(f.area_lat, f.profile_id, 'lat') end,
         case when f.modes <> 'online' then public.tutor_map_fuzz(f.area_lng, f.profile_id, 'lng') end
  from filtered f
  where f.avail_ok
    and case coalesce(p_mode, '')
          when 'in_person' then f.can_in_person
          when 'online' then f.can_online
          else f.can_in_person or f.can_online end
  order by score desc, f.dist nulls last
  limit least(coalesce(p_limit, 60), 100);
$$;
revoke execute on function public.tutor_search(double precision, double precision, text, text, int, numeric, text, text, text, boolean, int)
  from public, anon;
grant execute on function public.tutor_search(double precision, double precision, text, text, int, numeric, text, text, text, boolean, int)
  to authenticated;

-- ─── tutor_browse_requests ──────────────────────────────────────────────────
drop function if exists public.tutor_browse_requests(boolean);
create function public.tutor_browse_requests(p_only_my_subjects boolean default true)
returns table (id uuid, learner_id uuid, first_name text, for_child boolean, subject text, grade_level text,
               mode text, area_label text, distance_km numeric, max_rate numeric, availability jsonb,
               note text, created_at timestamptz, responded boolean, conversation_id uuid,
               map_lat double precision, map_lng double precision)
language sql stable security definer set search_path = public as $$
  select r.id, r.learner_id, coalesce(nullif(split_part(trim(p.name), ' ', 1), ''), 'A learner'),
         r.for_child, r.subject, r.grade_level, r.mode,
         r.area_label, round(d.dist::numeric, 1), r.max_rate, r.availability, r.note, r.created_at,
         x.tutor_id is not null, x.conversation_id,
         public.tutor_map_fuzz(r.area_lat, r.learner_id, 'lat'),
         public.tutor_map_fuzz(r.area_lng, r.learner_id, 'lng')
  from public.tutor_profiles m
  join public.tutor_requests r on r.status = 'open' and r.expires_at > now() and r.learner_id <> m.profile_id
  cross join lateral (select case when r.area_lat is null or m.area_lat is null then null else
        6371 * 2 * asin(sqrt(power(sin(radians(r.area_lat - m.area_lat) / 2), 2)
          + cos(radians(m.area_lat)) * cos(radians(r.area_lat)) * power(sin(radians(r.area_lng - m.area_lng) / 2), 2)))
      end as dist) d
  join public.profiles p on p.id = r.learner_id
  left join public.tutor_request_responses x on x.request_id = r.id and x.tutor_id = m.profile_id
  where m.profile_id = auth.uid() and public.tutor_is_live(m) and not public.am_i_suspended()
    and not public.tutor_blocked_between(r.learner_id, m.profile_id)
    and (not coalesce(p_only_my_subjects, true)
         or (r.subject = any(m.subjects) and r.grade_level = any(m.grade_levels)))
    and public.tutor_request_fits(m, r, d.dist)
  order by r.created_at desc
  limit 100;
$$;
revoke execute on function public.tutor_browse_requests(boolean) from public, anon;
grant execute on function public.tutor_browse_requests(boolean) to authenticated;
