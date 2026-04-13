require "./rule"

module Flaw
  # FLAW104 — AI-slop / broad swallow-rescue. `rescue; end`, `rescue ex; nil`,
  # `rescue Exception` — the "make it green" anti-pattern that hides real
  # errors (including security-relevant ones like TLS verification failure).
  class SwallowedRescue < Rule
    def id : String
      "FLAW104"
    end

    def title : String
      "Exception rescued and silenced"
    end

    def default_severity : Severity
      Severity::Low
    end

    def description : String
      <<-DESC
      A `rescue` clause catches everything and either does nothing or returns
      a generic fallback without logging. This hides genuine faults including
      security failures (TLS errors, auth failures). Catch the specific
      exception type and at minimum log it.
      DESC
    end

    def tag : String
      "ai-slop"
    end

    PATTERNS = [
      /\brescue\s*\n\s*end\b/,
      /\brescue\s*;\s*end\b/,
      /\brescue\s+(?:Exception|Object)\b/,
      /\brescue\s+\w+\s*$\s*nil\s*$\s*end\b/m,
    ]

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      # line-level scan for the simple forms
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        if m = line.match(/\brescue\s+(?:Exception|Object)\b/)
          results << finding(source, path, idx, m.begin(0) || 0,
            "Broad rescue (Exception/Object) — catch the specific type or at least log")
          next
        end
        if line =~ /\brescue\s*$/
          # look ahead for an empty body
          lines = source.split('\n')
          next_idx = idx
          if next_line = lines[next_idx]?
            if next_line.strip == "end" || next_line.strip == "nil"
              results << finding(source, path, idx, 0,
                "Empty rescue body — either handle the error or log and re-raise")
            end
          end
        end
      end
      results
    end
  end
end
