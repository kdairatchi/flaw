require "jwt"

def decode(token : String, key : String)
  JWT.decode(token, key, JWT::Algorithm::HS256)
end
