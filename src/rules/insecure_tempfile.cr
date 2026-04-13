require "./rule"

module Flaw
  # FLAW013 — Insecure tempfile. `/tmp/#{rand}` or `File.tempname` +
  # `File.write` without atomic O_EXCL | O_CREAT is a classic symlink/race
  # attack. Use `File.tempfile` which opens O_EXCL.
  class InsecureTempfile < Rule
    def id : String
      "FLAW013"
    end

    def title : String
      "Tempfile created without atomic O_EXCL"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def description : String
      <<-DESC
      A path under /tmp was built manually (or from `File.tempname`) and then
      written to. An attacker with local access can pre-create or symlink that
      path to clobber arbitrary files. Use `File.tempfile { |f| ... }` which
      opens with O_EXCL and a cryptographically random suffix.
      DESC
    end

    PATTERNS = [
      /File\.write\s*\(\s*File\.tempname\b/,
      /File\.write\s*\(\s*"\/tmp\/[^"]*\#\{/,
      /"\/tmp\/\#\{rand/,
    ]

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        PATTERNS.each do |re|
          if m = line.match(re)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Use File.tempfile { |f| ... } — it opens O_EXCL with a random suffix")
            break
          end
        end
      end
      results
    end
  end
end
