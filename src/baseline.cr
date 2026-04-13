require "json"

module Flaw
  # Baseline — capture current findings to a JSON file and suppress them on
  # future scans so teams can adopt flaw mid-project without a wall of red.
  # Match key: (rule_id, normalised file path, snippet). Line numbers shift;
  # the snippet lets a moved finding still match.
  module Baseline
    record Entry, rule_id : String, file : String, snippet : String do
      include JSON::Serializable
    end

    def self.save(findings : Array(Finding), path : String) : Nil
      entries = findings.map { |f| Entry.new(f.rule_id, f.file, f.snippet) }
      File.write(path, {
        "version"    => 1,
        "created_at" => Time.utc.to_s,
        "count"      => entries.size,
        "entries"    => entries,
      }.to_pretty_json)
    end

    def self.load(path : String) : Set(Tuple(String, String, String))
      set = Set(Tuple(String, String, String)).new
      return set unless File.exists?(path)
      raw = JSON.parse(File.read(path))
      raw["entries"].as_a.each do |e|
        set << {e["rule_id"].as_s, e["file"].as_s, e["snippet"].as_s}
      end
      set
    end

    def self.filter(findings : Array(Finding), baseline : Set(Tuple(String, String, String))) : Array(Finding)
      findings.reject { |f| baseline.includes?({f.rule_id, f.file, f.snippet}) }
    end
  end
end
