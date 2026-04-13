require "openssl"

ctx = OpenSSL::SSL::Context::Client.new
# Explicit TLS 1.2 minimum is fine
