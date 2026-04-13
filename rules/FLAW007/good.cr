# FLAW007 — fixed: path-only redirect, or host allowlist
ALLOWED_HOSTS = {"app.example.com", "docs.example.com"}

def safe_next(env, raw : String?)
  return "/" unless raw
  if raw.starts_with?("/") && !raw.starts_with?("//")
    env.redirect(raw)
  else
    uri = URI.parse(raw)
    if (host = uri.host) && ALLOWED_HOSTS.includes?(host)
      env.redirect(raw)
    else
      env.redirect("/")
    end
  end
end
