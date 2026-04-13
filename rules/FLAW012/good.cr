require "crypto/subtle"

def valid_token?(provided : String, expected : String) : Bool
  Crypto::Subtle.constant_time_compare(provided, expected)
end

def check_hmac(body_hmac : String, signature : String) : Bool
  Crypto::Subtle.constant_time_compare(body_hmac, signature)
end
