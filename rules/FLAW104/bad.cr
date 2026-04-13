def load_config
  File.read("config.yml")
rescue Exception
  nil
end

def ping
  HTTP::Client.get("/health")
rescue Object
  "down"
end
