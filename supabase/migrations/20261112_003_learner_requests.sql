-- ════════════════════════════════════════════════════════════════════════════
-- "Looking for a tutor" requests
-- Learners (or parents) post what they need; live tutors browse open requests and
-- can reply once per request, which starts a normal chat. Posting is the learner's
-- opt-in to being contacted, so this doesn't break the "tutors can't cold-message
-- learners" rule anywhere else.
--
-- Privacy rules baked in:
--   • Only LIVE tutors (approved, ID-verified, listed, not hidden) can browse.
--   • Requests for a child are only shown to tutors with a cleared, unexpired
--     Vulnerable Sector Check, and contain no child details beyond subject + grade band.
--   • Tutors see the poster's first name, neighbourhood label and rough distance —
--     never coordinates. Coordinates are rounded to ~1 km on save.
--   • Requests expire after 30 days; a learner can have at most 3 open at once.
--   • A tutor can reply to at most 20 requests per 24 h (anti-spam).
-- Safe to re-run.
-- ════════════════════════════════════════════════════════════════════════════

create table if not exists public.tutor_requests (
  id           uuid primary key default gen_random_uuid(),
  learner_id   uuid not null references public.profiles(id) on delete cascade,
  for_child    boolean not null default false,
  subject      text not null check (char_length(subject) between 1 and 60),
  grade_level  text not null check (char_length(grade_level) between 1 and 60),
  mode         text not null check (mode in ('in_person', 'online', 'either')),
  area_label   text check (char_length(area_label) <= 120),
  area_lat     double precision,
  area_lng     double precision,
  max_rate     numeric check (max_rate is null or (max_rate >= 0 and max_rate <= 500)),
  availability jsonb not null default '{}'::jsonb,
  note         text check (char_length(note) <= 500),
  status       text not null default 'open' check (status in ('open', 'closed')),
  created_at   timestamptz not null default now(),
  expires_at   timestamptz not null default now() + interval '30 days'
);
create index if not exists tutor_requests_open on public.tutor_requests (created_at desc) where status = 'open';
create index if not exists tutor_requests_learner on public.tutor_requests (learner_id, status);
alter table public.tutor_requests enable row level security;
-- Learners read their own; everything else goes through the functions below.
drop policy if exists treq_select on public.tutor_requests;
create policy treq_select on public.tutor_requests for select
  using (learner_id = auth.uid() or public.tutor_is_admin());

create table if not exists public.tutor_request_responses (
  request_id       uuid not null references public.tutor_requests(id) on delete cascade,
  tutor_id         uuid not null references public.profiles(id) on delete cascade,
  conversation_id  uuid references public.tutor_conversations(id) on delete set null,
  created_at       timestamptz not null default now(),
  primary key (request_id, tutor_id)
);
create index if not exists tutor_request_responses_tutor on public.tutor_request_responses (tutor_id, created_at);
alter table public.tutor_request_responses enable row level security;
drop policy if exists trr_select on public.tutor_request_responses;
create policy trr_select on public.tutor_request_responses for select
  using (tutor_id = auth.uid() or public.tutor_is_admin() or exists (
    select 1 from public.tutor_requests r where r.id = request_id and r.learner_id = auth.uid()));

-- ─── Learner side ───────────────────────────────────────────────────────────
create or replace function public.tutor_post_request(
  p_for_child boolean, p_subject text, p_grade text, p_mode text,
  p_area_label text, p_lat double precision, p_lng double precision,
  p_max_rate numeric, p_availability jsonb, p_note text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare rid uuid; n text := nullif(trim(coalesce(p_note, '')), '');
begin
  perform public.tutor_assert_active();
  if not exists (select 1 from public.tutor_members where profile_id = auth.uid() and role = 'learner') then
    return jsonb_build_object('ok', false, 'reason', 'not_learner');
  end if;
  if coalesce(trim(p_subject), '') = '' or coalesce(trim(p_grade), '') = '' then
    return jsonb_build_object('ok', false, 'reason', 'subject_or_grade');
  end if;
  if p_mode not in ('in_person', 'online', 'either') then
    return jsonb_build_object('ok', false, 'reason', 'mode');
  end if;
  if p_mode <> 'online' and (p_lat is null or p_lng is null or coalesce(trim(p_area_label), '') = '') then
    return jsonb_build_object('ok', false, 'reason', 'area_needed');
  end if;
  if n is not null and cardinality(public.tutor_moderate(n)) > 0 then
    return jsonb_build_object('ok', false, 'reason', 'note_contact');
  end if;
  if (select count(*) from public.tutor_requests
      where learner_id = auth.uid() and status = 'open' and expires_at > now()) >= 3 then
    return jsonb_build_object('ok', false, 'reason', 'too_many_requests');
  end if;
  insert into public.tutor_requests (learner_id, for_child, subject, grade_level, mode, area_label,
                                     area_lat, area_lng, max_rate, availability, note)
  values (auth.uid(), coalesce(p_for_child, false), trim(p_subject), trim(p_grade), p_mode,
          case when p_lat is null then null else left(trim(p_area_label), 120) end,
          round(p_lat::numeric, 2), round(p_lng::numeric, 2),
          p_max_rate, coalesce(p_availability, '{}'::jsonb), left(n, 500))
  returning id into rid;
  return jsonb_build_object('ok', true, 'id', rid);
end $$;

create or replace function public.tutor_close_request(p_request uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
begin
  perform public.tutor_assert_active();
  update public.tutor_requests set status = 'closed'
   where id = p_request and learner_id = auth.uid() and status = 'open';
  if not found then return jsonb_build_object('ok', false, 'reason', 'not_found'); end if;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.tutor_my_requests()
returns table (id uuid, for_child boolean, subject text, grade_level text, mode text, area_label text,
               max_rate numeric, note text, status text, created_at timestamptz, expires_at timestamptz,
               responses int)
language sql stable security definer set search_path = public as $$
  select r.id, r.for_child, r.subject, r.grade_level, r.mode, r.area_label, r.max_rate, r.note,
         case when r.status = 'open' and r.expires_at <= now() then 'expired' else r.status end,
         r.created_at, r.expires_at,
         (select count(*)::int from public.tutor_request_responses x where x.request_id = r.id)
  from public.tutor_requests r
  where r.learner_id = auth.uid()
  order by (r.status = 'open' and r.expires_at > now()) desc, r.created_at desc
  limit 20;
$$;

-- ─── Tutor side ─────────────────────────────────────────────────────────────
-- Can this tutor serve this request? (format, distance, and VSC for child requests)
create or replace function public.tutor_request_fits(t public.tutor_profiles, r public.tutor_requests, dist double precision)
returns boolean language sql stable as $$
  select (not r.for_child or public.tutor_minors_ok(t))
     and (
       (r.mode in ('online', 'either') and t.modes in ('online', 'both'))
       or (r.mode in ('in_person', 'either') and t.modes in ('in_person', 'both')
           and dist is not null and dist <= t.travel_km)
     );
$$;

create or replace function public.tutor_browse_requests(p_only_my_subjects boolean default true)
returns table (id uuid, learner_id uuid, first_name text, for_child boolean, subject text, grade_level text,
               mode text, area_label text, distance_km numeric, max_rate numeric, availability jsonb,
               note text, created_at timestamptz, responded boolean, conversation_id uuid)
language sql stable security definer set search_path = public as $$
  select r.id, r.learner_id, coalesce(nullif(split_part(trim(p.name), ' ', 1), ''), 'A learner'),
         r.for_child, r.subject, r.grade_level, r.mode,
         r.area_label, round(d.dist::numeric, 1), r.max_rate, r.availability, r.note, r.created_at,
         x.tutor_id is not null, x.conversation_id
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

create or replace function public.tutor_respond_request(p_request uuid, p_message text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare t public.tutor_profiles; r public.tutor_requests; cid uuid; d double precision;
        msg text := nullif(trim(coalesce(p_message, '')), '');
begin
  perform public.tutor_assert_active();
  select * into t from public.tutor_profiles where profile_id = auth.uid();
  if t is null or not public.tutor_is_live(t) then return jsonb_build_object('ok', false, 'reason', 'not_live'); end if;
  if msg is null or char_length(msg) > 1000 then return jsonb_build_object('ok', false, 'reason', 'message_length'); end if;
  select * into r from public.tutor_requests where id = p_request;
  if r is null or r.status <> 'open' or r.expires_at <= now() then
    return jsonb_build_object('ok', false, 'reason', 'request_closed');
  end if;
  if public.tutor_blocked_between(r.learner_id, auth.uid()) then raise exception 'blocked'; end if;
  d := case when r.area_lat is null or t.area_lat is null then null else
         6371 * 2 * asin(sqrt(power(sin(radians(r.area_lat - t.area_lat) / 2), 2)
           + cos(radians(t.area_lat)) * cos(radians(r.area_lat)) * power(sin(radians(r.area_lng - t.area_lng) / 2), 2))) end;
  if not public.tutor_request_fits(t, r, d) then return jsonb_build_object('ok', false, 'reason', 'request_not_fit'); end if;
  if exists (select 1 from public.tutor_request_responses where request_id = r.id and tutor_id = auth.uid()) then
    return jsonb_build_object('ok', false, 'reason', 'already_responded');
  end if;
  if (select count(*) from public.tutor_request_responses
      where tutor_id = auth.uid() and created_at > now() - interval '24 hours') >= 20 then
    return jsonb_build_object('ok', false, 'reason', 'reply_limit');
  end if;
  insert into public.tutor_conversations (tutor_id, learner_id) values (auth.uid(), r.learner_id)
    on conflict (tutor_id, learner_id) do update set last_message_at = now()
    returning id into cid;
  insert into public.tutor_request_responses (request_id, tutor_id, conversation_id)
    values (r.id, auth.uid(), cid);
  -- Context line, then the tutor's own message (moderated + notified by the existing triggers).
  insert into public.tutor_messages (conversation_id, sender_id, body, kind)
    values (cid, auth.uid(), 'Replied to your request: ' || r.subject || ' · ' || r.grade_level, 'system');
  insert into public.tutor_messages (conversation_id, sender_id, body, kind)
    values (cid, auth.uid(), msg, 'user');
  return jsonb_build_object('ok', true, 'conversation_id', cid);
end $$;

-- ─── Grants ─────────────────────────────────────────────────────────────────
grant execute on function
  public.tutor_post_request(boolean, text, text, text, text, double precision, double precision, numeric, jsonb, text),
  public.tutor_close_request(uuid), public.tutor_my_requests(),
  public.tutor_browse_requests(boolean), public.tutor_respond_request(uuid, text)
to authenticated;
revoke execute on function public.tutor_request_fits(public.tutor_profiles, public.tutor_requests, double precision)
  from public, anon;
