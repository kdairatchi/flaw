require "json"

# Write-only DTO — what the client is allowed to set
struct UpdateUser
  include JSON::Serializable
  property name : String
  property email : String
end

# Read-only response DTO — server-authoritative, never from_json'd
struct UserResponse
  include JSON::Serializable
  getter name : String
  getter email : String
  getter role : String
end
