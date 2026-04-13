require "openssl"

ctx = OpenSSL::SSL::Context::Client.new
# Default min is TLSv1.2 on modern OpenSSL; leave as-is.
