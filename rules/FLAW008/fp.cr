# FLAW008 — FP corpus: typed JSON::Serializable is safe
require "json"

struct Incoming
  include JSON::Serializable
  getter id : Int32
  getter name : String
end

payload = Incoming.from_json(body)
puts payload.id
