# FLAW010 — FP corpus: TLS left alone; context created without disabling verify
require "http/client"
require "openssl"

ctx = OpenSSL::SSL::Context::Client.new
client = HTTP::Client.new("api.example.com", tls: ctx)
client.get("/")
