require "./rule"

module Flaw
  class UnsafeYamlLoad < Rule
    def id : String
      "FLAW005"
    end

    def title : String
      "YAML parsed from potentially untrusted source"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def description : String
      <<-DESC
      `YAML.parse` or `YAML.parse_all` was called with a value that likely came
      from user input (ARGV, STDIN, request bodies, env-derived paths). Parse
      only trusted YAML, or validate the schema before use.
      DESC
    end

    PATTERNS = [
      /YAML\.parse(?:_all)?\s*\(\s*(?:STDIN|ARGV\[|request\.body|params\[|env\[)/,
      /YAML\.parse(?:_all)?\s*\(\s*File\.read\s*\(\s*(?:ARGV\[|params\[|env\[)/,
    ]

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        PATTERNS.each do |re|
          if m = line.match(re)
            results << finding(source, path, idx, m.begin(0) || 0,
              "YAML parsed from untrusted input — validate schema or use a safe loader")
            break
          end
        end
      end
      results
    end
  end
end
