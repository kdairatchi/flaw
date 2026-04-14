require "./rule"
require "./context"

module Flaw
  # FLAW135 — PII logged through common logger calls.
  class PiiInLog < Rule
    def id : String
      "FLAW135"
    end

    def title : String
      "PII in log"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      Logging email addresses, credentials, tokens, or other PII ends up
      in log sinks that usually have weaker access controls than the
      database. Redact or hash before emitting.
      DESC
    end

    LOG_CALL = /\b(?:logger?|log|console|Rails\.logger|Log)\.(?:debug|info|warn|warning|error|fatal|critical|log)\s*\(/
    PII_RX   = /\b(email|ssn|social_security|credit_card|card_number|cvv|password|passwd|pwd|secret|token|api_key|phone|address|dob|birth_date|full_name)\b/i

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless RuleContext.code_path?(path)
      return [] of Finding if RuleContext.test_path?(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        next unless line =~ LOG_CALL
        if m = line.match(PII_RX)
          results << finding(source, path, idx, m.begin(0) || 0,
            "PII field '#{m[1]}' logged — redact before emitting to logs")
        end
      end
      results
    end
  end
end
