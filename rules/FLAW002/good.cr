# FLAW002 — fixed: secrets read from environment
aws_key   = ENV["AWS_ACCESS_KEY"]? || raise "AWS_ACCESS_KEY missing"
gh_token  = ENV["GITHUB_TOKEN"]?
api_key   = ENV.fetch("STRIPE_SECRET_KEY")
password  = ENV["APP_PASSWORD"]? || "changeme"
