require "openssl"

def encrypt(data : Bytes, key : Bytes) : Bytes
  iv = "0123456789ab"
  cipher = OpenSSL::Cipher.new("aes-256-gcm")
  cipher.encrypt
  cipher.key = key
  cipher.iv = iv.to_slice
  cipher.update(data) + cipher.final
end
