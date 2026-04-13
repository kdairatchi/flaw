# FLAW009 — fixed: bcrypt for passwords, SHA-256+ for integrity
require "crypto/bcrypt/password"
require "digest/sha256"

def hash_password(password : String) : String
  Crypto::Bcrypt::Password.create(password, cost: 12).to_s
end

def verify_signature(body : String, signature : String) : Bool
  Digest::SHA256.hexdigest(body) == signature
end
