# FLAW005 — FP corpus: YAML parsed from trusted constants / embedded strings
require "yaml"

EMBEDDED = <<-YAML
name: flaw
port: 8080
YAML

data = YAML.parse(EMBEDDED)
puts data["name"]

# also: reading literal file path — still technically risky but not user-input
data2 = YAML.parse(File.read("/etc/flaw/static.yml"))
