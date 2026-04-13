# Public API — wildcard without credentials is allowed
def cors(env)
  env.response.headers["Access-Control-Allow-Origin"] = "*"
  env.response.headers["Access-Control-Allow-Methods"] = "GET"
end
