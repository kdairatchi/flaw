require "./rule"
require "./context"

module Flaw
  # FLAW125 — TOCTOU: existence check followed by open/read/write.
  class ToctouRace < Rule
    def id : String
      "FLAW125"
    end

    def title : String
      "TOCTOU race"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      Checking if a path exists and then opening it later is racy — an
      attacker can swap the path for a symlink between the two calls.
      Open the file directly and handle the error, or use openat with
      O_NOFOLLOW / Crystal File.open rescue pattern.
      DESC
    end

    EXISTS_RX = /(?:File\.exists?\?|os\.path\.exists|os\.path\.isfile|os\.access)\s*\(\s*([A-Za-z_][A-Za-z0-9_\.\[\]]*)/
    USE_RX    = /(?:open|File\.open|File\.read|File\.write|os\.open|io\.open)\s*\(\s*([A-Za-z_][A-Za-z0-9_\.\[\]]*)/

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless RuleContext.code_path?(path)
      return [] of Finding if RuleContext.test_path?(path)
      lines = source.split('\n')
      results = [] of Finding
      lines.each_with_index do |line, i|
        next if RuleContext.comment_only?(line)
        if m = line.match(EXISTS_RX)
          var = m[1]
          # look ahead up to 5 lines for a use with same var
          ((i + 1)..Math.min(i + 5, lines.size - 1)).each do |j|
            nxt = lines[j]
            next if RuleContext.comment_only?(nxt)
            if um = nxt.match(USE_RX)
              if um[1] == var
                results << finding(source, path, i + 1, m.begin(0) || 0,
                  "TOCTOU — existence check before open/read; attacker can race symlink in between")
                break
              end
            end
          end
        end
      end
      results
    end
  end
end
