-- Notification text without em dashes (display style: no dashes anywhere in the UI).
-- Same three functions as in 001, only the notification strings changed.

create or replace function public.tutor_respond_booking(p_booking uuid, p_accept boolean, p_reason text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare b public.tutor_bookings; t public.tutor_profiles; i int;
begin
  perform public.tutor_assert_active();
  select * into b from public.tutor_bookings where id = p_booking for update;
  if b is null or b.tutor_id <> auth.uid() then return jsonb_build_object('ok', false, 'reason', 'not_found'); end if;
  if b.status <> 'requested' then return jsonb_build_object('ok', false, 'reason', 'not_pending'); end if;
  if p_accept then
    select * into t from public.tutor_profiles where profile_id = b.tutor_id;
    if b.for_child and not public.tutor_minors_ok(t) then return jsonb_build_object('ok', false, 'reason', 'not_cleared_for_minors'); end if;
    if b.first_start_at < now() + interval '30 minutes' then return jsonb_build_object('ok', false, 'reason', 'start_passed'); end if;
    update public.tutor_bookings set status = 'confirmed', updated_at = now() where id = b.id;
    for i in 0 .. b.weeks - 1 loop
      insert into public.tutor_sessions (booking_id, tutor_id, learner_id, start_at, duration_min)
      values (b.id, b.tutor_id, b.learner_id, b.first_start_at + make_interval(weeks => i), b.duration_min);
    end loop;
    perform public.tutor_system_message(b.tutor_id, b.learner_id, b.tutor_id, '✅ Booking confirmed: ' || b.subject || ', first session ' || public.tutor_fmt_time(b.first_start_at) || '.');
    perform public.tutor_notify(b.learner_id, 'booking_confirmed', 'Booking confirmed',
      b.subject || ', first session ' || public.tutor_fmt_time(b.first_start_at) || '.', 'booking:' || b.id);
  else
    update public.tutor_bookings set status = 'declined', decline_reason = nullif(trim(p_reason), ''), updated_at = now() where id = b.id;
    perform public.tutor_system_message(b.tutor_id, b.learner_id, b.tutor_id, '↩️ Booking request declined' ||
      coalesce(': ' || nullif(trim(p_reason), ''), '.'));
    perform public.tutor_notify(b.learner_id, 'booking_declined', 'Booking request declined',
      b.subject || coalesce(': ' || nullif(trim(p_reason), ''), ''), 'booking:' || b.id);
  end if;
  return jsonb_build_object('ok', true);
end $$;

-- Learner withdraws a pending request, or either side ends a confirmed booking (all future sessions).
create or replace function public.tutor_cancel_booking(p_booking uuid, p_reason text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare b public.tutor_bookings; other uuid;
begin
  perform public.tutor_assert_active();
  select * into b from public.tutor_bookings where id = p_booking for update;
  if b is null or auth.uid() not in (b.tutor_id, b.learner_id) then return jsonb_build_object('ok', false, 'reason', 'not_found'); end if;
  if b.status not in ('requested', 'confirmed') then return jsonb_build_object('ok', false, 'reason', 'closed'); end if;
  other := case when auth.uid() = b.tutor_id then b.learner_id else b.tutor_id end;
  update public.tutor_sessions set status = 'cancelled', cancelled_by = auth.uid(), cancelled_at = now(),
         cancel_reason = nullif(trim(p_reason), ''), late_cancel = start_at < now() + interval '24 hours'
   where booking_id = b.id and status = 'scheduled' and start_at > now();
  update public.tutor_bookings set status = case when exists (select 1 from public.tutor_sessions where booking_id = b.id and status = 'completed')
                                                  then 'completed' else 'cancelled' end, updated_at = now()
   where id = b.id;
  perform public.tutor_system_message(b.tutor_id, b.learner_id, auth.uid(),
    '❌ ' || case when b.status = 'requested' then 'Booking request withdrawn' else 'Remaining sessions cancelled' end ||
    coalesce(': ' || nullif(trim(p_reason), ''), '.'));
  perform public.tutor_notify(other, 'cancelled', 'Booking cancelled', b.subject || coalesce(': ' || nullif(trim(p_reason), ''), ''), 'booking:' || b.id);
  return jsonb_build_object('ok', true);
end $$;

-- Cancellation window: 24 hours. Cancelling inside it is still allowed but recorded as a late cancellation.
create or replace function public.tutor_cancel_session(p_session uuid, p_reason text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare s public.tutor_sessions; b public.tutor_bookings; other uuid; late boolean;
begin
  perform public.tutor_assert_active();
  select * into s from public.tutor_sessions where id = p_session for update;
  if s is null or auth.uid() not in (s.tutor_id, s.learner_id) then return jsonb_build_object('ok', false, 'reason', 'not_found'); end if;
  if s.status <> 'scheduled' or s.start_at <= now() then return jsonb_build_object('ok', false, 'reason', 'not_cancellable'); end if;
  late := s.start_at < now() + interval '24 hours';
  update public.tutor_sessions set status = 'cancelled', cancelled_by = auth.uid(), cancelled_at = now(),
         cancel_reason = nullif(trim(p_reason), ''), late_cancel = late where id = s.id;
  select * into b from public.tutor_bookings where id = s.booking_id;
  if not exists (select 1 from public.tutor_sessions where booking_id = b.id and status = 'scheduled') then
    update public.tutor_bookings set status = case when exists (select 1 from public.tutor_sessions where booking_id = b.id and status = 'completed')
                                                    then 'completed' else 'cancelled' end, updated_at = now() where id = b.id;
  end if;
  other := case when auth.uid() = s.tutor_id then s.learner_id else s.tutor_id end;
  perform public.tutor_system_message(s.tutor_id, s.learner_id, auth.uid(),
    '❌ Session on ' || public.tutor_fmt_time(s.start_at) || ' cancelled' || case when late then ' (less than 24 h notice)' else '' end ||
    coalesce(': ' || nullif(trim(p_reason), ''), '.'));
  perform public.tutor_notify(other, 'cancelled', 'Session cancelled',
    b.subject || ' on ' || public.tutor_fmt_time(s.start_at) || case when late then ' (late cancellation)' else '' end, 'session:' || s.id);
  return jsonb_build_object('ok', true, 'late', late);
end $$;
