require "./rule"
require "./context"

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

    # .env.example and sample configs are *supposed* to contain placeholders.
    ALLOW_PATH = %r{(\.env\.example|\.env\.sample|\.env\.template|/examples?/|/samples?/|/templates?/|README|CHANGELOG)}i

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding if ALLOW_PATH.match(path)
      return [] of Finding if RuleContext.doc_path?(path)
      return [] of Finding if RuleContext.lock_path?(path)
      return [] of Finding if RuleContext.test_path?(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        # ignore lines that are *declaring* a constant of placeholders
        # (rule patterns, test data generators).
        next if line =~ /PATTERNS?\s*=|FIXTURES?\s*=|EXAMPLE_/
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
