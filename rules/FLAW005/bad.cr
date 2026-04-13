# FLAW005 — vulnerable: parsing YAML straight from untrusted sources
require "yaml"

config = YAML.parse(STDIN)
puts config

all = YAML.parse_all(ARGV[0])
pp all

user_path = params["config_path"]
settings = YAML.parse(File.read(params["config_path"]))
