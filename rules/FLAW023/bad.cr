require "jwt"

def decode(token : String)
  JWT.decode(token, nil, "none")
end

def decode_unverified(token : String, key : String)
  JWT.decode(token, key, verify: false)
end
