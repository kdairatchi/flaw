def cors(env)
  env.response.headers["Access-Control-Allow-Origin"] = "*"
  env.response.headers["Access-Control-Allow-Credentials"] = "true"
end

def cors_echo(env)
  env.response.headers["Access-Control-Allow-Origin"] = env.request.headers["Origin"]
  env.response.headers["Access-Control-Allow-Credentials"] = "true"
end
