require "./rule"

module Flaw
  # FLAW102 — placeholder secrets/URLs never replaced with real values.
  # These typically survive vibe-coding sessions where the author forgot to
  # wire up real config.
  class PlaceholderValue < Rule
    def id : String
      "FLAW102"
    end

    def title : String
      "Placeholder value left in source"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def tag : String
      "ai-slop"
    end

    def description : String
      <<-DESC
      A string literal matches a common placeholder that should have been
      replaced before shipping ("your-api-key-here", "REPLACE_ME",
      "<YOUR_TOKEN>", "TODO_FILL_ME", "changeme", "xxxxxxxxxx"). At best
      this is config that was never wired up; at worst it's a working path
      that lands on the placeholder string at runtime.
      DESC
    end

    PATTERNS = [
      /"(your[_\- ]?(api[_\- ]?key|token|secret|password|email))"/i,
      /"(replace[_\- ]?me|change[_\- ]?me|fill[_\- ]?me[_\- ]?in|insert[_\- ]?here)"/i,
      /"<\s*(YOUR|INSERT|TODO|REPLACE)[\w\- ]*>"/i,
      /"(todo[_\-]?fill[_\-]?me|placeholder)"/i,
      /"(x{8,}|X{8,})"/,
      /"(changeme|default[_\-]?password|password123|admin123|secret123)"/i,
      /"(example\.com\/api|localhost:\d+\/REPLACE)"/i,
    ]

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        PATTERNS.each do |re|
          if m = line.match(re)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Placeholder value '#{m[0]}' — replace with real config or ENV lookup")
            break
          end
        end
      end
      results
    end
  end
end
