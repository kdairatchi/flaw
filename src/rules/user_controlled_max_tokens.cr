require "./rule"
require "./context"

module Flaw
  # FLAW155 — LLM max_tokens / maxOutputTokens driven by request input
  # without a clamp. Billing DoS: a caller asks for 200K tokens and the
  # provider bills you per request.
  class UserControlledMaxTokens < Rule
    def id : String
      "FLAW155"
    end

    def title : String
      "User-controlled LLM max_tokens without clamp"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      An LLM call's `max_tokens` / `maxOutputTokens` parameter is set
      from a request-derived variable without a numeric clamp. A single
      malicious request can drive per-call billing to the API's cap —
      wrap the value in `min(req_value, HARD_CAP)` or ignore the
      client-supplied field entirely.
      DESC
    end

    MAX_TOKENS_RX = /\b(max_tokens|max_output_tokens|maxOutputTokens|maxTokens)\s*[:=]\s*([A-Za-z_][\w\.\[\]'"]*)/
    REQ_SRC_RX    = /\b(request\.|req\.(body|query|params|data)|event\.body|args\.|params\[|body\[|query\[|ctx\.(body|query|params|request)|request_body|payload\.)/
    CLAMP_RX      = /\b(min\(|Math\.min\(|clamp\(|MIN\(|cap\(|\.clamp\(|\?\?\s*\d)/

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless RuleContext.code_path?(path)
      return [] of Finding if RuleContext.test_path?(path)
      results = [] of Finding
      lines = source.lines
      lines.each_with_index do |line, i|
        next if RuleContext.comment_only?(line)
        next unless m = line.match(MAX_TOKENS_RX)
        val = m[2]
        next if val =~ /\A["']?\d+["']?\z/ # constant int / stringified int
        next if CLAMP_RX.match(line)
        window_start = Math.max(0, i - 8)
        window = lines[window_start..i].join('\n')
        next unless REQ_SRC_RX.match(window)
        results << finding(source, path, i + 1, m.begin(0) || 0,
          "#{m[1]} = #{val} is request-derived — clamp to a server-side cap")
      end
      results
    end
  end
end
