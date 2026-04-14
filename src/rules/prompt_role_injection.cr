require "./rule"
require "./context"

module Flaw
  # FLAW151 — user input interpolated into a system/assistant role.
  # OWASP LLM01. If a request body field ends up inside `role: "system"`
  # content, the caller controls the model's instructions.
  class PromptRoleInjection < Rule
    def id : String
      "FLAW151"
    end

    def title : String
      "User input interpolated into system/assistant role"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      A request-derived variable is interpolated into a `{"role":
      "system"}` or `{"role": "assistant"}` message — an OWASP LLM01
      prompt-injection primitive. Treat the system prompt as a trust
      boundary: never concatenate user input into it, or explicitly
      wrap and sanitize before doing so.
      DESC
    end

    ROLE_RX = /["']role["']\s*:\s*["'](system|assistant)["']/
    # Template interpolations that could carry user input.
    PY_TEMPLATE_RX = /f["'][^"']*\{[^}]+\}|\.format\(|%\s*\(/
    JS_TEMPLATE_RX = /`[^`]*\$\{[^}]+\}/
    # Obvious request-derived identifiers.
    REQ_IDENT_RX = /\b(request\.|req\.(body|query|params)|input\(|args\.|params\[|body\[|query\[|event\.body|ctx\.(body|query|params))/

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless RuleContext.code_path?(path)
      return [] of Finding if RuleContext.test_path?(path)
      results = [] of Finding
      lines = source.lines
      lines.each_with_index do |line, i|
        next if RuleContext.comment_only?(line)
        next unless m = line.match(ROLE_RX)
        # widen to the nearest 3 lines, sometimes role: and content: split.
        window_start = Math.max(0, i - 1)
        window_end = Math.min(lines.size - 1, i + 3)
        window = lines[window_start..window_end].join('\n')
        has_tmpl = PY_TEMPLATE_RX.match(window) || JS_TEMPLATE_RX.match(window)
        has_req = REQ_IDENT_RX.match(window)
        if has_tmpl && has_req
          results << finding(source, path, i + 1, m.begin(0) || 0,
            "Request-derived input interpolated into role='#{m[1]}' message")
        end
      end
      results
    end
  end
end
