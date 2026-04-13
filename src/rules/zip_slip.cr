require "./rule"

module Flaw
  # FLAW022 — Zip-slip. Extracting archive entries whose names contain
  # `..` lets the attacker write outside the target directory.
  class ZipSlip < Rule
    def id : String
      "FLAW022"
    end

    def title : String
      "Archive entry extracted without path normalization (zip-slip)"
    end

    def default_severity : Severity
      Severity::High
    end

    def description : String
      <<-DESC
      Iterating over a zip or tar archive and writing `entry.name` (or
      `entry.filename`, `entry.path`) directly under an output directory
      lets a malicious archive write to arbitrary paths via `../` in its
      entries. Normalize each path and verify it stays inside the output
      root before writing.
      DESC
    end

    # File.open(File.join(dest, entry.name), "w") without prior check
    PATTERNS = [
      /File\.open\s*\(\s*File\.join\([^)]*\bentry\.(?:name|filename|path)\b/,
      /File\.write\s*\(\s*File\.join\([^)]*\bentry\.(?:name|filename|path)\b/,
      /Dir\.mkdir\s*\(\s*File\.join\([^)]*\bentry\.(?:name|filename|path)\b/,
    ]

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        PATTERNS.each do |re|
          if m = line.match(re)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Archive entry written without normalization — expand_path + starts_with?(root) before File.open")
            break
          end
        end
      end
      results
    end
  end
end
