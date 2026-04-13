require "json"

struct UpdateUser
  include JSON::Serializable
  property name : String
  property email : String
  property role : String
  property is_admin : Bool
end

incoming = UpdateUser.from_json(request.body)
