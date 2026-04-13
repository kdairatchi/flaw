# FLAW008 — vulnerable: deserialize untrusted blob
require "json"

data = JSON.parse(STDIN)
pp data

raw = JSON.parse(request.body.not_nil!)
pp raw

cookie = JSON.parse(cookies["session"].value)
pp cookie
