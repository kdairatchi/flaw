# Constant URL, not user-controlled — should not fire
require "http/client"
HTTP::Client.get("https://api.example.com/status")
HTTP.get("https://prowlrbot.com/health")
