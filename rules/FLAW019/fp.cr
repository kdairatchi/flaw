# Not a cookie creation — should not fire
def parse_cookie_header(raw : String)
  raw.split(";").map(&.strip)
end
