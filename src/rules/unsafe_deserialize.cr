require "./rule"

module Flaw
  class UnsafeDeserialize < Rule
    def id : String
      "FLAW008"
    end

    def title : String
      "Deserialization of untrusted data"
    end

    def default_severity : Severity
      Severity::High
    end

    def description : String
      <<-DESC
      JSON / MessagePack / Marshal-style deserialization is called on data from
      STDIN, ARGV, an HTTP body, a cookie, or an env-derived path without a
      typed schema. Even without type-instantiation gadgets, untrusted input
      deserves schema-validation before use.
      DESC
    end

    PATTERNS = [
      /\bJSON\.parse\s*\(\s*(STDIN|ARGV\[|request\.body|params\[|env\[|cookies\[)/,
      /\bMessagePack\.unpack\s*\(\s*(STDIN|ARGV\[|request\.body|params\[|cookies\[)/,
      /\bJSON\.parse\s*\(\s*File\.read\s*\(\s*(ARGV\[|params\[|env\[)/,
    ]

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        PATTERNS.each do |re|
          if m = line.match(re)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Deserializing untrusted input — use a typed `from_json` on a validating struct")
            break
          end
        end
      end
      results
    end
  end
end
