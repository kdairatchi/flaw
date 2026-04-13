ALLOWED_ORIGINS = {"https://app.example.com", "https://admin.example.com"}

def cors(env)
  origin = env.request.headers["Origin"]?
  return unless origin && ALLOWED_ORIGINS.includes?(origin)
  # origin validated against ALLOWED_ORIGINS allowlist above
  env.response.headers["Access-Control-Allow-Origin"] = origin # ALLOWED_ORIGINS
  env.response.headers["Access-Control-Allow-Credentials"] = "true"
end
