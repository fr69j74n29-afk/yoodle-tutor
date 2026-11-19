-- ════════════════════════════════════════════════════════════════════════════
-- 014 (18 Nov 2026): requests for Grade 12 and below need a cleared Vulnerable Sector Check.
--
-- Before: a tutor without a cleared check could see (and reply to) any request not marked for_child.
-- Now: they also can't see or reply to a request whose grade level is Grade 12 or below, even if the
-- learner didn't mark it as for a child. Only "College / University" and "Adult learner" requests stay
-- open to them. Any other or unknown grade value counts as Grade 12 and below (fails closed).
--
-- tutor_request_fits() is used by both tutor_browse_requests() and tutor_respond_request(), so this one
-- change covers the tutor's request list, the request pins on their map and replying.
-- ════════════════════════════════════════════════════════════════════════════

create or replace function public.tutor_grade_is_k12(p_grade text)
returns boolean language sql immutable as $$
  select coalesce(p_grade, '') not in ('College / University', 'Adult learner');
$$;

create or replace function public.tutor_request_fits(t public.tutor_profiles, r public.tutor_requests, dist double precision)
returns boolean language sql stable as $$
  select ((not r.for_child and not public.tutor_grade_is_k12(r.grade_level)) or public.tutor_minors_ok(t))
     and (
       (r.mode in ('online', 'either') and t.modes in ('online', 'both'))
       or (r.mode in ('in_person', 'either') and t.modes in ('in_person', 'both')
           and dist is not null and dist <= t.travel_km)
     );
$$;
