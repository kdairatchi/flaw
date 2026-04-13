require "openssl"

ctx = OpenSSL::SSL::Context::Client.new
min_version = OpenSSL::SSL::TLSv1_0
