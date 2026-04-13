require "openssl"

def encrypt(data : Bytes, key : Bytes) : {Bytes, Bytes}
  iv = Random::Secure.random_bytes(12)
  cipher = OpenSSL::Cipher.new("aes-256-gcm")
  cipher.encrypt
  cipher.key = key
  cipher.iv = iv
  {iv, cipher.update(data) + cipher.final}
end
