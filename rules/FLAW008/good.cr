# FLAW008 — fixed: typed deserialization via JSON::Serializable
require "json"

struct CreateUser
  include JSON::Serializable
  getter name : String
  getter email : String
end

user = CreateUser.from_json(request.body.not_nil!)
puts user.name
