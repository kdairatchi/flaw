# FLAW102 — fixed: everything read from environment, with a real default
API_KEY  = ENV["APP_API_KEY"]? || raise "APP_API_KEY missing"
TOKEN    = ENV["APP_TOKEN"]?
ENDPOINT = ENV["APP_BASE_URL"]? || "https://api.prowlrbot.com"
