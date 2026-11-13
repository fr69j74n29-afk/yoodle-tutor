-- Service area is optional: it's only used to match learners for in-person lessons,
-- so online-only tutors (or tutors who'd rather not list an area) can still submit.
-- Tutors without an area still appear in online searches; they just can't be matched
-- by distance for in-person lessons.
create or replace function public.tutor_submit_profile()
returns jsonb language plpgsql security definer set search_path = public as $$
declare t public.tutor_profiles;
begin
  perform public.tutor_assert_active();
  select * into t from public.tutor_profiles where profile_id = auth.uid();
  if t is null then return jsonb_build_object('ok', false, 'reason', 'no_profile'); end if;
  if cardinality(t.subjects) = 0 or cardinality(t.grade_levels) = 0 or t.hourly_rate is null
     or coalesce(t.bio, '') = '' then
    return jsonb_build_object('ok', false, 'reason', 'incomplete');
  end if;
  if t.review_status in ('pending', 'approved') then
    return jsonb_build_object('ok', true, 'status', t.review_status);
  end if;
  perform public.tutor_bypass_on();
  update public.tutor_profiles set review_status = 'pending', review_note = null
    where profile_id = auth.uid();
  return jsonb_build_object('ok', true, 'status', 'pending');
end $$;
