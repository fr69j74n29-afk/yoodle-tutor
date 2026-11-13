-- ════════════════════════════════════════════════════════════════════════════
-- Yoodle Tutors (tutor.yoodle.ca) — database schema
-- Runs in the SAME Supabase project as yoodle.ca. Everything is new and prefixed
-- tutor_*; existing yoodle tables are only READ (profiles, admin_users, blocks,
-- identity_verifications) or reused as-is (blocks, am_i_suspended()).
--
-- Design rules baked in here:
--   • Accounts are adults (18+ attestation). There are NO child records: a child
--     session stores only subject + grade band + optional parent note.
--   • A parent's private label for a booking lives in its own table that only the
--     parent can read (the tutor never sees it).
--   • Tables are read through RLS; every state change (booking, cancel, complete,
--     review, admin decisions) goes through SECURITY DEFINER functions that check
--     the caller, so the browser can't skip a rule.
--   • Public tutor data is only exposed through tutor_search() / tutor_public_profile().
--
-- Run once in the SQL editor (or `supabase db push`). Safe to re-run: uses
-- IF NOT EXISTS / CREATE OR REPLACE where Postgres allows it.
-- ════════════════════════════════════════════════════════════════════════════

-- ─── Helpers ────────────────────────────────────────────────────────────────
create or replace function public.tutor_is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.admin_users a
                 where lower(a.email) = lower(coalesce(auth.jwt() ->> 'email', '')));
$$;

-- RPCs set this flag so the guard triggers let them write protected columns.
create or replace function public.tutor_bypass_on()
returns void language sql as $$ select set_config('tutor.bypass', 'on', true); $$;

create or replace function public.tutor_bypassing()
returns boolean language sql stable as $$
  select coalesce(current_setting('tutor.bypass', true), '') = 'on';
$$;

create or replace function public.tutor_blocked_between(a uuid, b uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.blocks
                 where (blocker_id = a and blocked_id = b) or (blocker_id = b and blocked_id = a));
$$;

create or replace function public.tutor_id_verified(p uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.identity_verifications
                 where profile_id = p and status = 'verified');
$$;

create or replace function public.tutor_assert_active()
returns void language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not_signed_in'; end if;
  if public.am_i_suspended() then raise exception 'suspended'; end if;
end $$;

-- ─── Accounts ───────────────────────────────────────────────────────────────
create table if not exists public.tutor_members (
  profile_id          uuid primary key references public.profiles(id) on delete cascade,
  role                text not null check (role in ('learner', 'tutor')),
  adult_confirmed_at  timestamptz not null,
  terms_accepted_at   timestamptz not null,
  created_at          timestamptz not null default now()
);
alter table public.tutor_members enable row level security;
drop policy if exists tm_select on public.tutor_members;
create policy tm_select on public.tutor_members for select
  using (profile_id = auth.uid() or public.tutor_is_admin());
drop policy if exists tm_insert on public.tutor_members;
create policy tm_insert on public.tutor_members for insert
  with check (profile_id = auth.uid());

-- ─── Tutor profiles ─────────────────────────────────────────────────────────
create table if not exists public.tutor_profiles (
  profile_id          uuid primary key references public.profiles(id) on delete cascade,
  headline            text check (char_length(headline) <= 80),
  bio                 text check (char_length(bio) <= 1500),
  subjects            text[] not null default '{}',
  grade_levels        text[] not null default '{}',
  hourly_rate         numeric(6,2) check (hourly_rate >= 0 and hourly_rate <= 500),
  modes               text not null default 'both' check (modes in ('in_person', 'online', 'both')),
  service_area        text check (char_length(service_area) <= 120), -- neighbourhood, shown publicly
  area_lat            double precision,  -- rounded to ~1 km by the guard trigger, never returned
  area_lng            double precision,
  travel_km           int not null default 10 check (travel_km between 1 and 50),
  availability        jsonb not null default '{}'::jsonb, -- {"mon":["morning","evening"], ...}
  listed              boolean not null default false,      -- tutor's own on/off switch
  -- set only by admins / RPCs (guard trigger):
  review_status       text not null default 'draft'
                        check (review_status in ('draft', 'pending', 'approved', 'rejected')),
  review_note         text,
  minors_status       text not null default 'none'
                        check (minors_status in ('none', 'submitted', 'cleared', 'rejected')),
  minors_file_path    text,
  minors_submitted_at timestamptz,
  minors_cleared_at   timestamptz,
  minors_expires_at   date,
  minors_note         text,
  admin_hidden        boolean not null default false, -- set when the account is suspended
  rating              numeric(3,2),
  review_count        int not null default 0,
  created_at          timestamptz not null default now(),
  updated_at          timestamptz not null default now()
);
alter table public.tutor_profiles enable row level security;
drop policy if exists tp_select on public.tutor_profiles;
create policy tp_select on public.tutor_profiles for select
  using (profile_id = auth.uid() or public.tutor_is_admin());
drop policy if exists tp_insert on public.tutor_profiles;
create policy tp_insert on public.tutor_profiles for insert
  with check (profile_id = auth.uid()
              and exists (select 1 from public.tutor_members m
                          where m.profile_id = auth.uid() and m.role = 'tutor'));
drop policy if exists tp_update on public.tutor_profiles;
create policy tp_update on public.tutor_profiles for update
  using (profile_id = auth.uid()) with check (profile_id = auth.uid());

create or replace function public.tutor_profiles_guard()
returns trigger language plpgsql as $$
begin
  new.updated_at := now();
  if new.area_lat is not null then new.area_lat := round(new.area_lat::numeric, 2); end if;
  if new.area_lng is not null then new.area_lng := round(new.area_lng::numeric, 2); end if;
  if public.tutor_bypassing() then return new; end if;
  if tg_op = 'INSERT' then
    new.review_status := 'draft'; new.review_note := null;
    new.minors_status := 'none'; new.minors_file_path := null; new.minors_submitted_at := null;
    new.minors_cleared_at := null; new.minors_expires_at := null; new.minors_note := null;
    new.admin_hidden := false; new.rating := null; new.review_count := 0;
  else
    new.review_status := old.review_status; new.review_note := old.review_note;
    new.minors_status := old.minors_status; new.minors_file_path := old.minors_file_path;
    new.minors_submitted_at := old.minors_submitted_at; new.minors_cleared_at := old.minors_cleared_at;
    new.minors_expires_at := old.minors_expires_at; new.minors_note := old.minors_note;
    new.admin_hidden := old.admin_hidden; new.rating := old.rating; new.review_count := old.review_count;
  end if;
  return new;
end $$;
drop trigger if exists tutor_profiles_guard on public.tutor_profiles;
create trigger tutor_profiles_guard before insert or update on public.tutor_profiles
  for each row execute function public.tutor_profiles_guard();

-- A tutor may teach under-18s only with a cleared, unexpired Vulnerable Sector Check.
create or replace function public.tutor_minors_ok(tp public.tutor_profiles)
returns boolean language sql stable as $$
  select tp.minors_status = 'cleared'
     and (tp.minors_expires_at is null or tp.minors_expires_at >= current_date);
$$;

-- Live = visible to learners: switched on, approved, ID verified, not hidden by admins.
create or replace function public.tutor_is_live(tp public.tutor_profiles)
returns boolean language sql stable security definer set search_path = public as $$
  select tp.listed and tp.review_status = 'approved' and not tp.admin_hidden
     and public.tutor_id_verified(tp.profile_id);
$$;

-- ─── Bookings & sessions ────────────────────────────────────────────────────
create table if not exists public.tutor_bookings (
  id              uuid primary key default gen_random_uuid(),
  tutor_id        uuid not null references public.profiles(id) on delete cascade,
  learner_id      uuid not null references public.profiles(id) on delete cascade,
  for_child       boolean not null,
  subject         text not null check (char_length(subject) <= 60),
  grade_level     text not null check (char_length(grade_level) <= 60),
  note            text check (char_length(note) <= 500),
  kind            text not null check (kind in ('trial', 'weekly')),
  mode            text not null check (mode in ('in_person', 'online')),
  first_start_at  timestamptz not null,
  duration_min    int not null check (duration_min in (30, 45, 60, 90, 120)),
  weeks           int not null default 1 check (weeks between 1 and 12),
  rate            numeric(6,2) not null,            -- agreed hourly rate, copied at booking
  status          text not null default 'requested'
                    check (status in ('requested', 'confirmed', 'declined', 'cancelled', 'completed')),
  decline_reason  text check (char_length(decline_reason) <= 300),
  safety_ack_at   timestamptz not null,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  check (tutor_id <> learner_id)
);
create index if not exists tutor_bookings_tutor on public.tutor_bookings (tutor_id, status);
create index if not exists tutor_bookings_learner on public.tutor_bookings (learner_id, status);
alter table public.tutor_bookings enable row level security;
drop policy if exists tb_select on public.tutor_bookings;
create policy tb_select on public.tutor_bookings for select
  using (auth.uid() in (tutor_id, learner_id) or public.tutor_is_admin());

-- Parent-only label ("Sam", "older one"…). The tutor can never read this table.
create table if not exists public.tutor_booking_labels (
  booking_id  uuid primary key references public.tutor_bookings(id) on delete cascade,
  learner_id  uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  label       text not null check (char_length(label) between 1 and 40)
);
alter table public.tutor_booking_labels enable row level security;
drop policy if exists tbl_all on public.tutor_booking_labels;
create policy tbl_all on public.tutor_booking_labels for all
  using (learner_id = auth.uid())
  with check (learner_id = auth.uid()
              and exists (select 1 from public.tutor_bookings b
                          where b.id = booking_id and b.learner_id = auth.uid()));

create table if not exists public.tutor_sessions (
  id                uuid primary key default gen_random_uuid(),
  booking_id        uuid not null references public.tutor_bookings(id) on delete cascade,
  tutor_id          uuid not null references public.profiles(id) on delete cascade,
  learner_id        uuid not null references public.profiles(id) on delete cascade,
  start_at          timestamptz not null,
  duration_min      int not null,
  status            text not null default 'scheduled' check (status in ('scheduled', 'completed', 'cancelled')),
  cancelled_by      uuid,
  cancel_reason     text check (char_length(cancel_reason) <= 300),
  cancelled_at      timestamptz,
  late_cancel       boolean not null default false,
  rescheduled_from  timestamptz,
  completed_at      timestamptz,
  amount            numeric(8,2),       -- rate × hours, logged at completion
  paid_off_app_at   timestamptz,        -- tutor ticks "paid" (payment happens off the app)
  covered           text check (char_length(covered) <= 1000),     -- about the session, not the child
  next_steps        text check (char_length(next_steps) <= 1000),
  reminded_24h_at   timestamptz,
  reminded_1h_at    timestamptz,
  created_at        timestamptz not null default now()
);
create index if not exists tutor_sessions_tutor on public.tutor_sessions (tutor_id, start_at);
create index if not exists tutor_sessions_learner on public.tutor_sessions (learner_id, start_at);
create index if not exists tutor_sessions_due on public.tutor_sessions (start_at) where status = 'scheduled';
alter table public.tutor_sessions enable row level security;
drop policy if exists ts_select on public.tutor_sessions;
create policy ts_select on public.tutor_sessions for select
  using (auth.uid() in (tutor_id, learner_id) or public.tutor_is_admin());

-- ─── Reviews ────────────────────────────────────────────────────────────────
create table if not exists public.tutor_reviews (
  id           uuid primary key default gen_random_uuid(),
  booking_id   uuid not null unique references public.tutor_bookings(id) on delete cascade,
  tutor_id     uuid not null references public.profiles(id) on delete cascade,
  reviewer_id  uuid not null references public.profiles(id) on delete cascade,
  rating       int not null check (rating between 1 and 5),
  body         text check (char_length(body) <= 1000),
  hidden       boolean not null default false,  -- admins can hide a review
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);
alter table public.tutor_reviews enable row level security;
drop policy if exists tr_select on public.tutor_reviews;
create policy tr_select on public.tutor_reviews for select
  using (reviewer_id = auth.uid() or tutor_id = auth.uid() or public.tutor_is_admin());

create or replace function public.tutor_refresh_rating(p_tutor uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform public.tutor_bypass_on();
  update public.tutor_profiles tp set
    rating = (select round(avg(rating)::numeric, 2) from public.tutor_reviews
              where tutor_id = p_tutor and not hidden),
    review_count = (select count(*) from public.tutor_reviews where tutor_id = p_tutor and not hidden)
  where tp.profile_id = p_tutor;
end $$;

-- Learners with 2+ completed sessions with this tutor ("repeat bookings").
create or replace function public.tutor_repeat_learners(p_tutor uuid)
returns int language sql stable security definer set search_path = public as $$
  select count(*)::int from (
    select learner_id from public.tutor_sessions
    where tutor_id = p_tutor and status = 'completed'
    group by learner_id having count(*) >= 2) x;
$$;

-- ─── Messaging ──────────────────────────────────────────────────────────────
create table if not exists public.tutor_conversations (
  id               uuid primary key default gen_random_uuid(),
  tutor_id         uuid not null references public.profiles(id) on delete cascade,
  learner_id       uuid not null references public.profiles(id) on delete cascade,
  created_at       timestamptz not null default now(),
  last_message_at  timestamptz not null default now(),
  unique (tutor_id, learner_id)
);
alter table public.tutor_conversations enable row level security;
drop policy if exists tc_select on public.tutor_conversations;
create policy tc_select on public.tutor_conversations for select
  using (auth.uid() in (tutor_id, learner_id) or public.tutor_is_admin());

create table if not exists public.tutor_messages (
  id               uuid primary key default gen_random_uuid(),
  conversation_id  uuid not null references public.tutor_conversations(id) on delete cascade,
  sender_id        uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  body             text not null check (char_length(body) between 1 and 2000),
  kind             text not null default 'user' check (kind in ('user', 'system')),
  flagged          boolean not null default false,
  flag_reasons     text[] not null default '{}',
  flag_reviewed_at timestamptz,
  created_at       timestamptz not null default now()
);
create index if not exists tutor_messages_conv on public.tutor_messages (conversation_id, created_at);
create index if not exists tutor_messages_flagged on public.tutor_messages (created_at) where flagged and flag_reviewed_at is null;
alter table public.tutor_messages enable row level security;
drop policy if exists tmsg_select on public.tutor_messages;
create policy tmsg_select on public.tutor_messages for select
  using (public.tutor_is_admin() or exists (
    select 1 from public.tutor_conversations c
    where c.id = conversation_id and auth.uid() in (c.tutor_id, c.learner_id)));
drop policy if exists tmsg_insert on public.tutor_messages;
create policy tmsg_insert on public.tutor_messages for insert
  with check (sender_id = auth.uid() and kind = 'user' and not public.am_i_suspended() and exists (
    select 1 from public.tutor_conversations c
    where c.id = conversation_id and auth.uid() in (c.tutor_id, c.learner_id)
      and not public.tutor_blocked_between(c.tutor_id, c.learner_id)));

create table if not exists public.tutor_conversation_reads (
  conversation_id  uuid not null references public.tutor_conversations(id) on delete cascade,
  profile_id       uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  last_read_at     timestamptz not null default now(),
  primary key (conversation_id, profile_id)
);
alter table public.tutor_conversation_reads enable row level security;
drop policy if exists tcr_all on public.tutor_conversation_reads;
create policy tcr_all on public.tutor_conversation_reads for all
  using (profile_id = auth.uid()) with check (profile_id = auth.uid());

-- Moderation: flag (not block) scam patterns and requests to move off the app.
-- The message is still delivered; both people see a warning and admins get it in the queue.
create or replace function public.tutor_moderate(p_body text)
returns text[] language plpgsql immutable as $$
declare r text[] := '{}'; b text := lower(p_body);
begin
  if b ~ '(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}' then r := r || 'phone_number'; end if;
  if b ~ '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' then r := r || 'email_address'; end if;
  if b ~ '(whats ?app|telegram|signal app|snapchat|snap me|wechat|kik|instagram|insta\M|\mdm me|text me|call me|my number|my cell|off (the )?app|outside (of )?(the )?app)'
    then r := r || 'off_app'; end if;
  if b ~ '(gift ?cards?|western union|moneygram|bitcoin|crypto|wire transfer|cashier.?s cheque|overpa(y|id)|pay (me )?(in advance|up ?front)|deposit (first|up ?front)|send (me )?(the|your) code|verification code|bank (login|password))'
    then r := r || 'scam'; end if;
  return r;
end $$;

create or replace function public.tutor_messages_before()
returns trigger language plpgsql as $$
begin
  if new.kind = 'user' then
    new.flag_reasons := public.tutor_moderate(new.body);
    new.flagged := cardinality(new.flag_reasons) > 0;
  end if;
  new.created_at := now();
  return new;
end $$;
drop trigger if exists tutor_messages_before on public.tutor_messages;
create trigger tutor_messages_before before insert on public.tutor_messages
  for each row execute function public.tutor_messages_before();

-- ─── Notifications (in-app; reminders created by tutor_send_reminders) ───────
create table if not exists public.tutor_notifications (
  id          uuid primary key default gen_random_uuid(),
  profile_id  uuid not null references public.profiles(id) on delete cascade,
  kind        text not null,   -- booking_request|booking_confirmed|booking_declined|cancelled|rescheduled|message|review|reminder|completed|verification
  title       text not null,
  body        text,
  link        text,            -- in-app route, e.g. 'session:<id>' or 'chat:<id>'
  read_at     timestamptz,
  created_at  timestamptz not null default now()
);
create index if not exists tutor_notifications_me on public.tutor_notifications (profile_id, created_at desc);
alter table public.tutor_notifications enable row level security;
drop policy if exists tn_select on public.tutor_notifications;
create policy tn_select on public.tutor_notifications for select using (profile_id = auth.uid());
drop policy if exists tn_update on public.tutor_notifications;
create policy tn_update on public.tutor_notifications for update
  using (profile_id = auth.uid()) with check (profile_id = auth.uid());

create or replace function public.tutor_notify(p_to uuid, p_kind text, p_title text, p_body text, p_link text)
returns void language sql security definer set search_path = public as $$
  insert into public.tutor_notifications (profile_id, kind, title, body, link)
  values (p_to, p_kind, p_title, p_body, p_link);
$$;
revoke execute on function public.tutor_notify(uuid, text, text, text, text) from public, anon, authenticated;

create or replace function public.tutor_system_message(p_tutor uuid, p_learner uuid, p_sender uuid, p_body text)
returns uuid language plpgsql security definer set search_path = public as $$
declare cid uuid;
begin
  insert into public.tutor_conversations (tutor_id, learner_id) values (p_tutor, p_learner)
    on conflict (tutor_id, learner_id) do update set last_message_at = now()
    returning id into cid;
  insert into public.tutor_messages (conversation_id, sender_id, body, kind)
    values (cid, p_sender, p_body, 'system');
  return cid;
end $$;
revoke execute on function public.tutor_system_message(uuid, uuid, uuid, text) from public, anon, authenticated;

-- New message → bump conversation + notify the other person (at most one unread
-- message notification per conversation, so a busy chat doesn't flood the bell).
create or replace function public.tutor_messages_after()
returns trigger language plpgsql security definer set search_path = public as $$
declare c public.tutor_conversations; other uuid; nm text;
begin
  update public.tutor_conversations set last_message_at = new.created_at
    where id = new.conversation_id returning * into c;
  if new.kind <> 'user' then return new; end if;
  other := case when new.sender_id = c.tutor_id then c.learner_id else c.tutor_id end;
  if not exists (select 1 from public.tutor_notifications
                 where profile_id = other and kind = 'message' and read_at is null
                   and link = 'chat:' || new.conversation_id) then
    select coalesce(name, 'Someone') into nm from public.profiles where id = new.sender_id;
    perform public.tutor_notify(other, 'message', 'New message from ' || nm,
                                left(new.body, 120), 'chat:' || new.conversation_id);
  end if;
  return new;
end $$;
drop trigger if exists tutor_messages_after on public.tutor_messages;
create trigger tutor_messages_after after insert on public.tutor_messages
  for each row execute function public.tutor_messages_after();

-- ─── Reports ────────────────────────────────────────────────────────────────
create table if not exists public.tutor_reports (
  id               uuid primary key default gen_random_uuid(),
  reporter_id      uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  reported_id      uuid not null references public.profiles(id) on delete cascade,
  reason           text not null check (char_length(reason) <= 80),
  details          text check (char_length(details) <= 1000),
  conversation_id  uuid references public.tutor_conversations(id) on delete set null,
  booking_id       uuid references public.tutor_bookings(id) on delete set null,
  status           text not null default 'open' check (status in ('open', 'resolved')),
  resolution       text,
  resolved_by      uuid,
  resolved_at      timestamptz,
  created_at       timestamptz not null default now(),
  check (reporter_id <> reported_id)
);
alter table public.tutor_reports enable row level security;
drop policy if exists trp_insert on public.tutor_reports;
create policy trp_insert on public.tutor_reports for insert with check (reporter_id = auth.uid());
drop policy if exists trp_select on public.tutor_reports;
create policy trp_select on public.tutor_reports for select
  using (reporter_id = auth.uid() or public.tutor_is_admin());

-- ═══ RPCs: account & tutor profile ═══════════════════════════════════════════
create or replace function public.tutor_me()
returns jsonb language sql stable security definer set search_path = public as $$
  select jsonb_build_object(
    'member', (select to_jsonb(m) from public.tutor_members m where m.profile_id = auth.uid()),
    'tutor', (select to_jsonb(t) - 'area_lat' - 'area_lng' from public.tutor_profiles t where t.profile_id = auth.uid()),
    'id_verified', public.tutor_id_verified(auth.uid()),
    'suspended', public.am_i_suspended());
$$;

create or replace function public.tutor_submit_profile()
returns jsonb language plpgsql security definer set search_path = public as $$
declare t public.tutor_profiles;
begin
  perform public.tutor_assert_active();
  select * into t from public.tutor_profiles where profile_id = auth.uid();
  if t is null then return jsonb_build_object('ok', false, 'reason', 'no_profile'); end if;
  if cardinality(t.subjects) = 0 or cardinality(t.grade_levels) = 0 or t.hourly_rate is null
     or coalesce(t.bio, '') = '' or coalesce(t.service_area, '') = '' then
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

-- Called after the tutor uploads their Vulnerable Sector Check to storage (bucket tutor-vsc/<uid>/…)
create or replace function public.tutor_submit_vsc(p_path text)
returns jsonb language plpgsql security definer set search_path = public as $$
begin
  perform public.tutor_assert_active();
  if p_path is null or split_part(p_path, '/', 1) <> auth.uid()::text then
    return jsonb_build_object('ok', false, 'reason', 'bad_path');
  end if;
  perform public.tutor_bypass_on();
  update public.tutor_profiles set minors_status = 'submitted', minors_file_path = p_path,
         minors_submitted_at = now(), minors_note = null
   where profile_id = auth.uid() and minors_status <> 'cleared';
  if not found then return jsonb_build_object('ok', false, 'reason', 'no_profile_or_cleared'); end if;
  return jsonb_build_object('ok', true);
end $$;

-- ═══ RPCs: search ════════════════════════════════════════════════════════════
-- p_mode: 'in_person' | 'online' | null (either). p_day: mon..sun, p_time: morning|afternoon|evening.
-- p_for_child = true → only tutors with a cleared Vulnerable Sector Check.
create or replace function public.tutor_search(
  p_lat double precision, p_lng double precision,
  p_subject text default null, p_grade text default null,
  p_max_km int default 25, p_max_rate numeric default null,
  p_mode text default null, p_day text default null, p_time text default null,
  p_for_child boolean default false, p_limit int default 60)
returns table (
  profile_id uuid, name text, headline text, subjects text[], grade_levels text[],
  hourly_rate numeric, modes text, service_area text, distance_km numeric,
  rating numeric, review_count int, repeat_learners int, minors_cleared boolean,
  match_score numeric)
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
         )::numeric, 1) as score
  from filtered f
  where f.avail_ok
    and case coalesce(p_mode, '')
          when 'in_person' then f.can_in_person
          when 'online' then f.can_online
          else f.can_in_person or f.can_online end
  order by score desc, f.dist nulls last
  limit least(coalesce(p_limit, 60), 100);
$$;

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
    'id_verified', true, 'minors_cleared', public.tutor_minors_ok(t),
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

-- ═══ RPCs: messaging ═════════════════════════════════════════════════════════
-- Learners start chats with live tutors. Tutors can't cold-message learners.
create or replace function public.tutor_start_conversation(p_tutor uuid)
returns uuid language plpgsql security definer set search_path = public as $$
declare t public.tutor_profiles; cid uuid;
begin
  perform public.tutor_assert_active();
  select id into cid from public.tutor_conversations where tutor_id = p_tutor and learner_id = auth.uid();
  if cid is not null then return cid; end if;
  select * into t from public.tutor_profiles where profile_id = p_tutor;
  if t is null or not public.tutor_is_live(t) then raise exception 'tutor_unavailable'; end if;
  if public.tutor_blocked_between(p_tutor, auth.uid()) then raise exception 'blocked'; end if;
  insert into public.tutor_conversations (tutor_id, learner_id) values (p_tutor, auth.uid())
    on conflict (tutor_id, learner_id) do update set tutor_id = excluded.tutor_id
    returning id into cid;
  return cid;
end $$;

create or replace function public.tutor_my_conversations()
returns table (conversation_id uuid, other_id uuid, other_name text, i_am_tutor boolean,
               last_body text, last_kind text, last_at timestamptz, unread boolean, blocked boolean)
language sql stable security definer set search_path = public as $$
  select c.id, o.id, coalesce(o.name, 'Yoodler'), c.tutor_id = auth.uid(),
         lm.body, lm.kind, c.last_message_at,
         lm.sender_id is distinct from auth.uid() and lm.created_at > coalesce(r.last_read_at, 'epoch'),
         public.tutor_blocked_between(c.tutor_id, c.learner_id)
  from public.tutor_conversations c
  join public.profiles o on o.id = case when c.tutor_id = auth.uid() then c.learner_id else c.tutor_id end
  left join lateral (select body, kind, sender_id, created_at from public.tutor_messages m
                     where m.conversation_id = c.id order by created_at desc limit 1) lm on true
  left join public.tutor_conversation_reads r on r.conversation_id = c.id and r.profile_id = auth.uid()
  where auth.uid() in (c.tutor_id, c.learner_id) and lm.created_at is not null
  order by c.last_message_at desc;
$$;

create or replace function public.tutor_mark_read(p_conversation uuid)
returns void language sql security definer set search_path = public as $$
  insert into public.tutor_conversation_reads (conversation_id, profile_id, last_read_at)
  select p_conversation, auth.uid(), now()
  where exists (select 1 from public.tutor_conversations c
                where c.id = p_conversation and auth.uid() in (c.tutor_id, c.learner_id))
  on conflict (conversation_id, profile_id) do update set last_read_at = now();
  update public.tutor_notifications set read_at = now()
   where profile_id = auth.uid() and read_at is null and link = 'chat:' || p_conversation;
$$;

-- ═══ RPCs: booking lifecycle ═════════════════════════════════════════════════
create or replace function public.tutor_fmt_time(ts timestamptz)
returns text language sql stable as $$
  select to_char(ts at time zone 'America/Toronto', 'Dy Mon DD, HH12:MI AM');
$$;

create or replace function public.tutor_request_booking(
  p_tutor uuid, p_for_child boolean, p_subject text, p_grade text, p_note text,
  p_kind text, p_mode text, p_start timestamptz, p_duration int, p_weeks int, p_safety_ack boolean)
returns jsonb language plpgsql security definer set search_path = public as $$
declare t public.tutor_profiles; bid uuid; me_name text; who text;
begin
  perform public.tutor_assert_active();
  if not exists (select 1 from public.tutor_members where profile_id = auth.uid() and role = 'learner') then
    return jsonb_build_object('ok', false, 'reason', 'not_learner'); end if;
  if not coalesce(p_safety_ack, false) then return jsonb_build_object('ok', false, 'reason', 'safety_ack'); end if;
  select * into t from public.tutor_profiles where profile_id = p_tutor;
  if t is null or not public.tutor_is_live(t) then return jsonb_build_object('ok', false, 'reason', 'tutor_unavailable'); end if;
  if public.tutor_blocked_between(p_tutor, auth.uid()) then return jsonb_build_object('ok', false, 'reason', 'blocked'); end if;
  if p_for_child and not public.tutor_minors_ok(t) then return jsonb_build_object('ok', false, 'reason', 'not_cleared_for_minors'); end if;
  if not (p_subject = any(t.subjects)) or not (p_grade = any(t.grade_levels)) then
    return jsonb_build_object('ok', false, 'reason', 'subject_or_grade'); end if;
  if p_mode not in ('in_person', 'online')
     or (p_mode = 'in_person' and t.modes = 'online') or (p_mode = 'online' and t.modes = 'in_person') then
    return jsonb_build_object('ok', false, 'reason', 'mode'); end if;
  if p_start < now() + interval '2 hours' or p_start > now() + interval '120 days' then
    return jsonb_build_object('ok', false, 'reason', 'start_time'); end if;
  if p_kind = 'trial' then p_weeks := 1;
  elsif p_kind <> 'weekly' or p_weeks not between 2 and 12 then return jsonb_build_object('ok', false, 'reason', 'weeks'); end if;
  if exists (select 1 from public.tutor_bookings where learner_id = auth.uid() and tutor_id = p_tutor and status = 'requested') then
    return jsonb_build_object('ok', false, 'reason', 'already_requested'); end if;

  insert into public.tutor_bookings (tutor_id, learner_id, for_child, subject, grade_level, note, kind, mode,
                                     first_start_at, duration_min, weeks, rate, safety_ack_at)
  values (p_tutor, auth.uid(), p_for_child, p_subject, p_grade, nullif(trim(p_note), ''), p_kind, p_mode,
          p_start, p_duration, p_weeks, t.hourly_rate, now())
  returning id into bid;

  select coalesce(name, 'A learner') into me_name from public.profiles where id = auth.uid();
  who := case when p_for_child then 'for their child' else 'for themselves' end;
  perform public.tutor_system_message(p_tutor, auth.uid(), auth.uid(),
    '📅 Booking request: ' || p_subject || ' (' || p_grade || '), ' ||
    case when p_kind = 'trial' then 'trial session' else 'weekly × ' || p_weeks end ||
    ', starting ' || public.tutor_fmt_time(p_start) || '.');
  perform public.tutor_notify(p_tutor, 'booking_request', 'New booking request',
    me_name || ' asked for ' || p_subject || ' ' || who || ', starting ' || public.tutor_fmt_time(p_start) || '.',
    'booking:' || bid);
  return jsonb_build_object('ok', true, 'booking_id', bid);
end $$;

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
      b.subject || ' — first session ' || public.tutor_fmt_time(b.first_start_at) || '.', 'booking:' || b.id);
  else
    update public.tutor_bookings set status = 'declined', decline_reason = nullif(trim(p_reason), ''), updated_at = now() where id = b.id;
    perform public.tutor_system_message(b.tutor_id, b.learner_id, b.tutor_id, '↩️ Booking request declined' ||
      coalesce(': ' || nullif(trim(p_reason), ''), '.'));
    perform public.tutor_notify(b.learner_id, 'booking_declined', 'Booking request declined',
      b.subject || coalesce(' — ' || nullif(trim(p_reason), ''), ''), 'booking:' || b.id);
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
  perform public.tutor_notify(other, 'cancelled', 'Booking cancelled', b.subject || coalesce(' — ' || nullif(trim(p_reason), ''), ''), 'booking:' || b.id);
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
    b.subject || ' on ' || public.tutor_fmt_time(s.start_at) || case when late then ' — late cancellation' else '' end, 'session:' || s.id);
  return jsonb_build_object('ok', true, 'late', late);
end $$;

-- Reschedule: only while more than 24 h before the session; inside the window, cancel instead.
create or replace function public.tutor_reschedule_session(p_session uuid, p_new_start timestamptz)
returns jsonb language plpgsql security definer set search_path = public as $$
declare s public.tutor_sessions; b public.tutor_bookings; other uuid;
begin
  perform public.tutor_assert_active();
  select * into s from public.tutor_sessions where id = p_session for update;
  if s is null or auth.uid() not in (s.tutor_id, s.learner_id) then return jsonb_build_object('ok', false, 'reason', 'not_found'); end if;
  if s.status <> 'scheduled' then return jsonb_build_object('ok', false, 'reason', 'not_scheduled'); end if;
  if s.start_at < now() + interval '24 hours' then return jsonb_build_object('ok', false, 'reason', 'inside_window'); end if;
  if p_new_start < now() + interval '2 hours' or p_new_start > now() + interval '120 days' then
    return jsonb_build_object('ok', false, 'reason', 'start_time'); end if;
  update public.tutor_sessions set rescheduled_from = coalesce(rescheduled_from, start_at), start_at = p_new_start,
         reminded_24h_at = null, reminded_1h_at = null where id = s.id;
  select * into b from public.tutor_bookings where id = s.booking_id;
  other := case when auth.uid() = s.tutor_id then s.learner_id else s.tutor_id end;
  perform public.tutor_system_message(s.tutor_id, s.learner_id, auth.uid(),
    '🔁 Session moved from ' || public.tutor_fmt_time(s.start_at) || ' to ' || public.tutor_fmt_time(p_new_start) || '.');
  perform public.tutor_notify(other, 'rescheduled', 'Session rescheduled',
    b.subject || ' moved to ' || public.tutor_fmt_time(p_new_start) || '.', 'session:' || s.id);
  return jsonb_build_object('ok', true);
end $$;

-- Tutor marks a session complete and logs it (amount = agreed rate × length). Payment is settled off the app.
create or replace function public.tutor_complete_session(p_session uuid, p_covered text, p_next text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare s public.tutor_sessions; b public.tutor_bookings;
begin
  perform public.tutor_assert_active();
  select * into s from public.tutor_sessions where id = p_session for update;
  if s is null or s.tutor_id <> auth.uid() then return jsonb_build_object('ok', false, 'reason', 'not_found'); end if;
  if s.status <> 'scheduled' then return jsonb_build_object('ok', false, 'reason', 'not_scheduled'); end if;
  if s.start_at > now() + interval '15 minutes' then return jsonb_build_object('ok', false, 'reason', 'not_started'); end if;
  select * into b from public.tutor_bookings where id = s.booking_id;
  update public.tutor_sessions set status = 'completed', completed_at = now(),
         amount = round(b.rate * s.duration_min / 60.0, 2),
         covered = nullif(trim(p_covered), ''), next_steps = nullif(trim(p_next), '')
   where id = s.id;
  if not exists (select 1 from public.tutor_sessions where booking_id = b.id and status = 'scheduled') then
    update public.tutor_bookings set status = 'completed', updated_at = now() where id = b.id;
  end if;
  perform public.tutor_system_message(s.tutor_id, s.learner_id, auth.uid(),
    '✅ Session on ' || public.tutor_fmt_time(s.start_at) || ' marked complete. Session notes are in Sessions.');
  perform public.tutor_notify(s.learner_id, 'completed', 'Session complete',
    'Your tutor added notes for ' || b.subject || '. How did it go? Leave a review.', 'session:' || s.id);
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.tutor_mark_paid(p_session uuid, p_paid boolean)
returns jsonb language plpgsql security definer set search_path = public as $$
begin
  update public.tutor_sessions set paid_off_app_at = case when p_paid then now() else null end
   where id = p_session and tutor_id = auth.uid() and status = 'completed';
  if not found then return jsonb_build_object('ok', false, 'reason', 'not_found'); end if;
  return jsonb_build_object('ok', true);
end $$;

-- One review per booking (editable), after at least one completed session.
create or replace function public.tutor_submit_review(p_booking uuid, p_rating int, p_body text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare b public.tutor_bookings; nm text; is_new boolean;
begin
  perform public.tutor_assert_active();
  select * into b from public.tutor_bookings where id = p_booking;
  if b is null or b.learner_id <> auth.uid() then return jsonb_build_object('ok', false, 'reason', 'not_found'); end if;
  if p_rating not between 1 and 5 then return jsonb_build_object('ok', false, 'reason', 'rating'); end if;
  if not exists (select 1 from public.tutor_sessions where booking_id = b.id and status = 'completed') then
    return jsonb_build_object('ok', false, 'reason', 'no_completed_session'); end if;
  is_new := not exists (select 1 from public.tutor_reviews where booking_id = b.id);
  insert into public.tutor_reviews (booking_id, tutor_id, reviewer_id, rating, body)
  values (b.id, b.tutor_id, auth.uid(), p_rating, nullif(trim(p_body), ''))
  on conflict (booking_id) do update set rating = excluded.rating, body = excluded.body, updated_at = now();
  perform public.tutor_refresh_rating(b.tutor_id);
  if is_new then
    select coalesce(split_part(name, ' ', 1), 'A learner') into nm from public.profiles where id = auth.uid();
    perform public.tutor_notify(b.tutor_id, 'review', 'New review: ' || repeat('★', p_rating), nm || ' reviewed your ' || b.subject || ' sessions.', 'reviews');
  end if;
  return jsonb_build_object('ok', true);
end $$;

-- ═══ Session reminders ═══════════════════════════════════════════════════════
-- Creates in-app reminders 24 h and 1 h before each session. Scheduled below with pg_cron
-- (every 10 min) when that extension is enabled; otherwise call it from any scheduler.
create or replace function public.tutor_send_reminders()
returns int language plpgsql security definer set search_path = public as $$
declare s record; n int := 0;
begin
  for s in select ss.*, b.subject from public.tutor_sessions ss join public.tutor_bookings b on b.id = ss.booking_id
           where ss.status = 'scheduled' and ss.start_at > now()
             and ((ss.reminded_24h_at is null and ss.start_at <= now() + interval '24 hours')
               or (ss.reminded_1h_at is null and ss.start_at <= now() + interval '1 hour')) loop
    if s.start_at <= now() + interval '1 hour' and s.reminded_1h_at is null then
      perform public.tutor_notify(s.tutor_id, 'reminder', 'Session in 1 hour', s.subject || ' at ' || public.tutor_fmt_time(s.start_at), 'session:' || s.id);
      perform public.tutor_notify(s.learner_id, 'reminder', 'Session in 1 hour', s.subject || ' at ' || public.tutor_fmt_time(s.start_at), 'session:' || s.id);
      update public.tutor_sessions set reminded_1h_at = now(), reminded_24h_at = coalesce(reminded_24h_at, now()) where id = s.id;
    else
      perform public.tutor_notify(s.tutor_id, 'reminder', 'Session tomorrow', s.subject || ' at ' || public.tutor_fmt_time(s.start_at), 'session:' || s.id);
      perform public.tutor_notify(s.learner_id, 'reminder', 'Session tomorrow', s.subject || ' at ' || public.tutor_fmt_time(s.start_at), 'session:' || s.id);
      update public.tutor_sessions set reminded_24h_at = now() where id = s.id;
    end if;
    n := n + 1;
  end loop;
  return n;
end $$;
revoke execute on function public.tutor_send_reminders() from public, anon, authenticated;

do $$ begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.unschedule(jobid) from cron.job where jobname = 'tutor-reminders';
    perform cron.schedule('tutor-reminders', '*/10 * * * *', 'select public.tutor_send_reminders()');
  else
    raise notice 'pg_cron not enabled: enable it (Database → Extensions) and re-run this block to schedule session reminders.';
  end if;
end $$;

-- ═══ Admin RPCs (admin_users only) ═══════════════════════════════════════════
create or replace function public.tutor_admin_assert()
returns void language plpgsql stable security definer set search_path = public as $$
begin if not public.tutor_is_admin() then raise exception 'not_admin'; end if; end $$;

create or replace function public.tutor_admin_queue()
returns jsonb language plpgsql stable security definer set search_path = public as $$
begin
  perform public.tutor_admin_assert();
  return jsonb_build_object(
    'profiles', coalesce((select jsonb_agg(x order by x.updated_at) from (
        select t.profile_id, p.name, u.email, t.headline, t.bio, t.subjects, t.grade_levels, t.hourly_rate,
               t.modes, t.service_area, t.review_status, t.review_note, t.updated_at,
               public.tutor_id_verified(t.profile_id) as id_verified
        from public.tutor_profiles t join public.profiles p on p.id = t.profile_id
        left join auth.users u on u.id = t.profile_id
        where t.review_status = 'pending') x), '[]'::jsonb),
    'checks', coalesce((select jsonb_agg(x order by x.minors_submitted_at) from (
        select t.profile_id, p.name, u.email, t.minors_status, t.minors_file_path, t.minors_submitted_at,
               public.tutor_id_verified(t.profile_id) as id_verified
        from public.tutor_profiles t join public.profiles p on p.id = t.profile_id
        left join auth.users u on u.id = t.profile_id
        where t.minors_status = 'submitted') x), '[]'::jsonb),
    'reports', coalesce((select jsonb_agg(x order by x.created_at desc) from (
        select r.*, rp.name as reporter_name, dp.name as reported_name
        from public.tutor_reports r
        left join public.profiles rp on rp.id = r.reporter_id
        left join public.profiles dp on dp.id = r.reported_id
        where r.status = 'open') x), '[]'::jsonb),
    'flagged', coalesce((select jsonb_agg(x order by x.created_at desc) from (
        select m.id, m.conversation_id, m.body, m.flag_reasons, m.created_at, m.sender_id, sp.name as sender_name,
               c.tutor_id, c.learner_id
        from public.tutor_messages m join public.tutor_conversations c on c.id = m.conversation_id
        left join public.profiles sp on sp.id = m.sender_id
        where m.flagged and m.flag_reviewed_at is null
        limit 200) x), '[]'::jsonb),
    'hidden', coalesce((select jsonb_agg(jsonb_build_object('profile_id', t.profile_id, 'name', p.name))
        from public.tutor_profiles t join public.profiles p on p.id = t.profile_id where t.admin_hidden), '[]'::jsonb));
end $$;

create or replace function public.tutor_admin_review_profile(p_tutor uuid, p_approve boolean, p_note text default null)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform public.tutor_admin_assert();
  perform public.tutor_bypass_on();
  update public.tutor_profiles set review_status = case when p_approve then 'approved' else 'rejected' end,
         review_note = nullif(trim(p_note), '') where profile_id = p_tutor;
  perform public.tutor_notify(p_tutor, 'verification',
    case when p_approve then 'Your tutor profile is approved' else 'Your tutor profile needs changes' end,
    coalesce(nullif(trim(p_note), ''), case when p_approve then 'Switch on your listing to appear in search.' else 'Open your profile to see what to fix.' end),
    'profile');
end $$;

create or replace function public.tutor_admin_review_check(p_tutor uuid, p_clear boolean, p_expires date default null, p_note text default null)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform public.tutor_admin_assert();
  perform public.tutor_bypass_on();
  update public.tutor_profiles set
    minors_status = case when p_clear then 'cleared' else 'rejected' end,
    minors_cleared_at = case when p_clear then now() else null end,
    minors_expires_at = case when p_clear then p_expires else null end,
    minors_note = nullif(trim(p_note), '')
  where profile_id = p_tutor;
  perform public.tutor_notify(p_tutor, 'verification',
    case when p_clear then 'Background check cleared' else 'Background check not accepted' end,
    coalesce(nullif(trim(p_note), ''), case when p_clear then 'You now show "Available for students under 18".' else 'Open your profile for details.' end),
    'profile');
end $$;

create or replace function public.tutor_admin_resolve_report(p_report uuid, p_resolution text)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform public.tutor_admin_assert();
  update public.tutor_reports set status = 'resolved', resolution = nullif(trim(p_resolution), ''),
         resolved_by = auth.uid(), resolved_at = now() where id = p_report;
end $$;

create or replace function public.tutor_admin_clear_flag(p_message uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform public.tutor_admin_assert();
  update public.tutor_messages set flag_reviewed_at = now() where id = p_message;
end $$;

-- Hide/unhide a tutor listing (used alongside yoodle's admin_suspend_user when suspending).
create or replace function public.tutor_admin_set_hidden(p_profile uuid, p_hidden boolean)
returns void language plpgsql security definer set search_path = public as $$
begin
  perform public.tutor_admin_assert();
  perform public.tutor_bypass_on();
  update public.tutor_profiles set admin_hidden = p_hidden where profile_id = p_profile;
  if p_hidden then
    update public.tutor_sessions set status = 'cancelled', cancelled_by = auth.uid(), cancelled_at = now(),
           cancel_reason = 'Account suspended by Yoodle'
     where status = 'scheduled' and start_at > now() and (tutor_id = p_profile or learner_id = p_profile);
    update public.tutor_bookings set status = 'cancelled', updated_at = now()
     where status in ('requested', 'confirmed') and (tutor_id = p_profile or learner_id = p_profile)
       and not exists (select 1 from public.tutor_sessions s where s.booking_id = tutor_bookings.id and s.status = 'scheduled');
  end if;
end $$;

-- ─── Grants ─────────────────────────────────────────────────────────────────
grant execute on function public.tutor_me(), public.tutor_submit_profile(), public.tutor_submit_vsc(text),
  public.tutor_search(double precision, double precision, text, text, int, numeric, text, text, text, boolean, int),
  public.tutor_public_profile(uuid), public.tutor_start_conversation(uuid), public.tutor_my_conversations(),
  public.tutor_mark_read(uuid),
  public.tutor_request_booking(uuid, boolean, text, text, text, text, text, timestamptz, int, int, boolean),
  public.tutor_respond_booking(uuid, boolean, text), public.tutor_cancel_booking(uuid, text),
  public.tutor_cancel_session(uuid, text), public.tutor_reschedule_session(uuid, timestamptz),
  public.tutor_complete_session(uuid, text, text), public.tutor_mark_paid(uuid, boolean),
  public.tutor_submit_review(uuid, int, text),
  public.tutor_admin_queue(), public.tutor_admin_review_profile(uuid, boolean, text),
  public.tutor_admin_review_check(uuid, boolean, date, text), public.tutor_admin_resolve_report(uuid, text),
  public.tutor_admin_clear_flag(uuid), public.tutor_admin_set_hidden(uuid, boolean)
to authenticated;
revoke execute on function public.tutor_refresh_rating(uuid) from public, anon, authenticated;
revoke execute on function public.tutor_bypass_on() from public, anon, authenticated;

-- ─── Realtime (chat + notification bell) ────────────────────────────────────
do $$ begin
  begin alter publication supabase_realtime add table public.tutor_messages; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.tutor_notifications; exception when duplicate_object then null; end;
end $$;

-- ─── Storage: Vulnerable Sector Check uploads (private) ─────────────────────
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('tutor-vsc', 'tutor-vsc', false, 10485760, array['application/pdf', 'image/jpeg', 'image/png', 'image/heic'])
on conflict (id) do nothing;

drop policy if exists tutor_vsc_insert on storage.objects;
create policy tutor_vsc_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'tutor-vsc' and (storage.foldername(name))[1] = auth.uid()::text);
drop policy if exists tutor_vsc_select on storage.objects;
create policy tutor_vsc_select on storage.objects for select to authenticated
  using (bucket_id = 'tutor-vsc' and ((storage.foldername(name))[1] = auth.uid()::text or public.tutor_is_admin()));
