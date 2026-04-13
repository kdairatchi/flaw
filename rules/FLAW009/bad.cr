# FLAW009 — vulnerable: MD5/SHA1 for passwords and signatures
require "digest"

def hash_password(password : String) : String
  Digest::MD5.hexdigest(password)
end

def verify_signature(body : String, signature : String) : Bool
  Digest::SHA1.hexdigest(body) == signature
end
