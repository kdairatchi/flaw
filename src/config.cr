require "yaml"

module Flaw
  class Config
    DEFAULT_EXCLUDES = %w[lib/ .git/ bin/ .shards/ rules/]

    getter excludes : Array(String)
    getter rule_overrides : Hash(String, RuleOverride)

    struct RuleOverride
      getter severity : Severity?
      getter ignore : Array(String)
      getter disabled : Bool

      def initialize(@severity = nil, @ignore = [] of String, @disabled = false)
      end
    end

    def initialize(@excludes = DEFAULT_EXCLUDES.dup, @rule_overrides = {} of String => RuleOverride)
    end

    def self.load(path : String) : Config
      return Config.new unless File.exists?(path)
      raw = YAML.parse(File.read(path))
      excludes = (raw["exclude"]?.try(&.as_a?) || ([] of YAML::Any)).map(&.as_s)
      excludes.concat(DEFAULT_EXCLUDES)
      overrides = {} of String => RuleOverride
      raw["rules"]?.try &.as_h.each do |k, v|
        sev = v["severity"]?.try { |s| Severity.parse?(s.as_s) }
        ignore = (v["ignore"]?.try(&.as_a?) || ([] of YAML::Any)).map(&.as_s)
        disabled = v["disabled"]?.try(&.as_bool?) || false
        overrides[k.as_s] = RuleOverride.new(sev, ignore, disabled)
      end
      new(excludes.uniq, overrides)
    end

    def excluded?(path : String) : Bool
      excludes.any? { |pat| path.includes?(pat) }
    end
  end
end
