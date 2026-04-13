# FLAW010 — fixed: default verification left intact
require "http/client"

client = HTTP::Client.new("api.example.com", tls: true)
response = client.get("/secrets")
