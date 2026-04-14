require "./rule"
require "./context"

module Flaw
  # FLAW152 — tool/function-call result appended into next prompt without
  # a fence. OWASP LLM01 via indirect injection: if the tool result is
  # raw, attacker-controlled content passes straight into the model's
  # instructions.
  class ToolResultUnfenced < Rule
    def id : String
      "FLAW152"
    end

    def title : String
      "Tool result appended to prompt without fence"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      A `{"role": "tool"}` / `{"role": "function"}` message carries a bare
      variable into the conversation. Tool output is untrusted — wrap it
      in a delimiter (e.g. `<tool_result>…</tool_result>`) or explicitly
      sanitize before appending so injected instructions can't escape.
      DESC
    end

    TOOL_ROLE_RX      = /["']role["']\s*:\s*["'](tool|function)["']/
    BARE_CONTENT_RX   = /["']content["']\s*:\s*([A-Za-z_][A-Za-z0-9_\.\[\]]*)\s*[,}]/
    SANITIZER_HINT_RX = /<tool_result|<\/tool_result|sanitize|escape|fence|bleach|DOMPurify|```/i

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless RuleContext.code_path?(path)
      return [] of Finding if RuleContext.test_path?(path)
      results = [] of Finding
      lines = source.lines
      lines.each_with_index do |line, i|
        next if RuleContext.comment_only?(line)
        next unless role_m = line.match(TOOL_ROLE_RX)
        window_start = Math.max(0, i - 3)
        window_end = Math.min(lines.size - 1, i + 3)
        window = lines[window_start..window_end].join('\n')
        next if SANITIZER_HINT_RX.match(window)
        if m = window.match(BARE_CONTENT_RX)
          ident = m[1]
          next if ident =~ /\A(True|False|None|null|undefined)\z/
          results << finding(source, path, i + 1, role_m.begin(0) || 0,
            "tool role carries bare '#{ident}' — fence or sanitize before append")
        end
      end
      results
    end
  end
end
