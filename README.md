# yoodle-tutor

Yoodle Tutors — **tutor.yoodle.ca** (GitHub Pages). Built the same way as yoodle.ca (`yoodle-web`): no framework and no build step. The whole app is one `index.html`, with the same sage design system and the same Supabase project, so people sign in with their existing Yoodle accounts.

| File | What it is |
|---|---|
| `index.html` | The app: landing and sign-in, find a tutor, booking, sessions and calendar, messages, notifications, profile, tutor profile editor |
| `admin.html` | Admin queue: tutor approvals, background checks, reports, flagged messages, suspensions |
| `supabase/migrations/20261111_001_tutor_schema.sql` | All tables, security rules, RPCs, the reminder job, realtime and the storage bucket (everything is prefixed `tutor_`) |

## Setup (once)

1. **Run the migration.** Paste `supabase/migrations/20261111_001_tutor_schema.sql` into the Supabase SQL editor for the yoodle.ca project and run it. It only creates new `tutor_*` objects plus a private `tutor-vsc` storage bucket. It reads these existing yoodle objects, which must exist: `profiles`, `admin_users`, `blocks`, `identity_verifications`, `am_i_suspended()`, `my_blocked_ids()`, `admin_suspend_user()`.
2. **Session reminders.** Enable the `pg_cron` extension (Database → Extensions), then re-run the last `do $$ … pg_cron … $$` block in the migration. Without pg_cron no reminders are created.
3. **Sign-in redirects.** In Authentication → URL Configuration, add `https://tutor.yoodle.ca` (and `http://localhost:8000` for local testing) to the allowed redirect URLs.
4. **Run locally:** `python -m http.server 8000`, then open http://localhost:8000. Admin: http://localhost:8000/admin.html.

## How the rules are enforced

- **Accounts:** a one-time step after sign-in asks the person to choose *learner* or *tutor*, confirm they're 18 or older, and accept the terms and safety guidelines (`tutor_members`). Children never get accounts.
- **Child privacy:** a child booking stores only the subject, a grade band and an optional parent note. The parent's private label is kept in `tutor_booking_labels`, which only the parent can read. No names, photos or birthdates are stored.
- **Tutors in search** must have their listing switched on and a complete profile (subjects, grades, rate, bio). ID verification (Stripe, through yoodle.ca's `identity_verifications`) and admin review are no longer required to go live (migration 010); a verified ID shows as a ✓ ID badge. Yoodle can still take a tutor down (`admin_hidden`, a rejected review, or a yoodle.ca suspension).
- **yoodle.ca helpers who picked "Tutoring"** also appear on the Find map as purple pins, until they have a live tutor profile (`tutor_map_tutors`, source `yoodle`). They can't be booked here, are never shown as cleared for under-18s, and the pin sheet links to their yoodle.ca page (no contact button when searching for a child).
- **Under-18 sessions** need a cleared, unexpired Vulnerable Sector Check. Tutors without one are filtered out of child searches, and the database rejects child bookings and acceptances for them.
- **State changes in RPCs:** every booking, cancellation, reschedule, completion, review and admin decision goes through a `security definer` RPC that checks who is calling. Guard triggers stop tutors from editing their own approval, check status or rating.
- **Cancellation window:** sessions can be rescheduled up to 24 hours before they start. A cancellation inside 24 hours is still allowed but is recorded as a late cancellation.
- **Message moderation:** the `tutor_moderate()` trigger flags phone numbers, email addresses, requests to move off the app, and scam payment wording. Flagged messages are still delivered, but both people see a warning and the message lands in the admin queue.
- **Blocks** use yoodle's shared `blocks` table. Blocking someone on either site applies on both.

## Not done yet

- **Push and email notifications.** Notifications are in-app only: the bell, with live updates. Push would need its own OneSignal app for the tutor.yoodle.ca domain, and email would need an edge function.
- **In-app payments.** Agreed rates are shown and completed sessions are logged, but money is settled off the app. Holding payment until a session is marked complete would need Stripe Connect.
- **ID verification on this site.** Tutors verify on yoodle.ca with the same account; this site only reads the result. Running Stripe Identity here would need the yoodle edge functions to accept tutor.yoodle.ca as a return URL.
- **Time zone.** Times in system messages and notifications are formatted in Toronto time (`tutor_fmt_time`). The app itself shows each viewer's local time.
