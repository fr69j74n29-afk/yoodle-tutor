-- 004 revoked from anon, but Postgres also grants EXECUTE to PUBLIC on new functions,
-- which anon inherits. Revoke that; `authenticated` keeps its explicit grant from 003.
revoke execute on function
  public.tutor_post_request(boolean, text, text, text, text, double precision, double precision, numeric, jsonb, text),
  public.tutor_close_request(uuid), public.tutor_my_requests(),
  public.tutor_browse_requests(boolean), public.tutor_respond_request(uuid, text)
from public, anon;
