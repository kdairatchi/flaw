require "http/cookie"

def set_session(token : String)
  HTTP::Cookie.new("session", token, secure: true, http_only: true, samesite: :strict)
end
