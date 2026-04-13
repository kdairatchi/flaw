require "./rule"

module Flaw
  class PathTraversal < Rule
    def id : String
      "FLAW006"
    end

    def title : String
      "File access with user-controlled path"
    end

    def default_severity : Severity
      Severity::High
    end

    def description : String
      <<-DESC
      File.open / File.read / File.write receives a path assembled from user input
      (`params[...]`, `ARGV[...]`, `request.body`, interpolated query values)
      without normalisation or allowlisting. Attacker may escape the intended
      directory via `../`.
      DESC
    end

    USER_SRC = /(params\[|ARGV\[|request\.|env\[|query_params)/

    PATTERNS = [
      /\bFile\.(open|read|read_lines|write|exists\?|delete)\s*\([^)]*\#\{[^}]+\}[^)]*\)/,
      /\bFile\.(open|read|read_lines|write|exists\?|delete)\s*\(\s*(params\[|ARGV\[|request\.|env\[)/,
    ]

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        PATTERNS.each do |re|
          if m = line.match(re)
            # reduce FP: require a user-input hint somewhere on the line
            next unless line =~ USER_SRC || line.includes?("\#{")
            results << finding(source, path, idx, m.begin(0) || 0,
              "File path built from user input — normalise via File.expand_path and check it stays inside an allowed root")
            break
          end
        end
      end
      results
    end
  end
end
