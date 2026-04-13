require "json"

struct Profile
  include JSON::Serializable
  property name : String
  property email : String
  property bio : String
end
