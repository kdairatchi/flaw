# FLAW010 — vulnerable: TLS verification disabled
require "http/client"
require "openssl"

ctx = OpenSSL::SSL::Context::Client.new
ctx.verify_mode = OpenSSL::SSL::VerifyMode::NONE

client = HTTP::Client.new("api.example.com", tls: ctx)
response = client.get("/secrets")
