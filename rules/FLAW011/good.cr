require "http/client"
require "uri"

ALLOWED = {"api.example.com", "cdn.example.com"}

def fetch_preview(env)
  raw = env.params.query["url"]
  uri = URI.parse(raw)
  host = uri.host || return
  return unless ALLOWED.includes?(host)
  HTTP::Client.get(uri.to_s)
end
