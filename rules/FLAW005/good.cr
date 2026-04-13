# FLAW005 — fixed: parse YAML only from trusted paths, validate schema
require "yaml"

struct AppConfig
  include YAML::Serializable
  getter name : String
  getter port : Int32
end

trusted_path = "/etc/myapp/config.yml"
config = AppConfig.from_yaml(File.read(trusted_path))
puts config.name
