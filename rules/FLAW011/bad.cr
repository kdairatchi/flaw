require "http/client"

def fetch_preview(env)
  url = env.params.query["url"]
  HTTP::Client.get("https://#{url}")
end

def relay(host : String)
  client = HTTP::Client.new(host)
  client.get("/")
end
