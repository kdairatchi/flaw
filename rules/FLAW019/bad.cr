require "http/cookie"

def set_session(token : String)
  HTTP::Cookie.new("session", token)
end
