require "openssl"

def encrypt(data : Bytes, key : Bytes) : Bytes
  cipher = OpenSSL::Cipher.new("aes-256-gcm")
  cipher.encrypt
  cipher.key = key
  cipher.random_iv
  cipher.update(data) + cipher.final
end
