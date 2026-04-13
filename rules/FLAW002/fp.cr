# FLAW002 — FP corpus: named-assign patterns that should NOT fire
api_key  = ENV["STRIPE_KEY"]?
password = "changeme"
token    = "your_token_here"
secret   = "xxxxxxxxxxxxxxxx"
pwd      = "placeholder_pwd_0000"
# low-entropy repeated string should skip
auth     = "aaaaaaaaaaaaaaaaaaaa"
