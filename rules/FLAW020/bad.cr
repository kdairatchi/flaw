require "openssl"

def encrypt(data : Bytes, key : Bytes) : Bytes
  cipher = OpenSSL::Cipher.new("aes-128-ecb")
  cipher.encrypt
  cipher.key = key
  cipher.update(data) + cipher.final
end
