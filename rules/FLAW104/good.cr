def load_config
  File.read("config.yml")
rescue ex : File::NotFoundError
  Log.warn { "config missing: #{ex.message}" }
  nil
end
