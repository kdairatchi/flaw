require "./rule"
require "./context"

module Flaw
  # FLAW104 — AI-slop / broad swallow-rescue. `rescue; end`, `rescue ex; nil`,
  # `rescue Exception` — the "make it green" anti-pattern that hides real
  # errors (including security-relevant ones like TLS verification failure).
  # Also covers the same anti-pattern in Python (`except: pass`), JS/TS
  # (`catch (e) {}`), and Go (`if err != nil { }`).
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
      An exception handler catches everything and either does nothing or returns
      a generic fallback without logging. This hides genuine faults including
      security failures (TLS errors, auth failures). Catch the specific
      exception type and at minimum log it.
      DESC
    end

    def tag : String
      "ai-slop"
    end

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      lines = source.split('\n')

      cr_rb = path.ends_with?(".cr") || path.ends_with?(".rb")
      py = path.ends_with?(".py")
      js_ts = %w(.js .jsx .ts .tsx .mjs .cjs).any? { |e| path.ends_with?(e) }
      go = path.ends_with?(".go")

      lines.each_with_index do |line, i|
        idx = i + 1
        next if RuleContext.comment_only?(line)

        if cr_rb
          if m = line.match(/\brescue\s+(?:Exception|Object)\b/)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Broad rescue (Exception/Object) — catch the specific type or at least log")
            next
          end
          if line =~ /\brescue\s*$/
            if next_line = lines[idx]?
              if next_line.strip == "end"
                results << finding(source, path, idx, 0,
                  "Empty rescue body — either handle the error or log and re-raise")
                next
              end
            end
          end
        end

        if py
          stripped = line.rstrip
          if stripped =~ /^\s*except\s*:\s*$/ || stripped =~ /^\s*except\s+Exception\s*:\s*$/
            if next_line = lines[idx]?
              if next_line.strip == "pass"
                results << finding(source, path, idx, 0,
                  "Bare/broad except with `pass` — catches everything and silences it")
                next
              end
            end
          end
        end

        if js_ts
          if m = line.match(/\bcatch\s*(?:\(\s*\w*\s*\))?\s*\{\s*\}/)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Empty catch block — error silently discarded")
            next
          end
        end

        if go
          if m = line.match(/\bif\s+err\s*!=\s*nil\s*\{\s*\}/)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Empty `if err != nil {}` block — error is checked but not handled")
            next
          end
        end
      end

      results
    end
  end
end
