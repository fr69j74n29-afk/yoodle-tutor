-- Supabase's default privileges let `anon` execute new public functions. The request
-- functions already return nothing without a signed-in user, but make it explicit.
revoke execute on function
  public.tutor_post_request(boolean, text, text, text, text, double precision, double precision, numeric, jsonb, text),
  public.tutor_close_request(uuid), public.tutor_my_requests(),
  public.tutor_browse_requests(boolean), public.tutor_respond_request(uuid, text),
  public.tutor_request_fits(public.tutor_profiles, public.tutor_requests, double precision)
from anon;
