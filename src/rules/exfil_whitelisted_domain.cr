require "./rule"
require "./context"

module Flaw
  # FLAW156 — agent tool handler makes outbound HTTP where URL is not a
  # literal. Cowork-class exfil: the model instructs the handler to reach
  # a whitelisted but attacker-controlled host.
  class ExfilWhitelistedDomain < Rule
    def id : String
      "FLAW156"
    end

    def title : String
      "Tool handler makes outbound request to non-literal URL"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      A function registered as an agent/tool handler (e.g. `@tool`,
      `@mcp.tool`, or defined under `tools/` or `mcp/`) issues an
      outbound HTTP call with a URL derived from a variable or
      f-string. The model can steer the URL to any reachable host —
      including whitelisted domains that re-emit data. Pin URLs to a
      server-side allowlist before the request.
      DESC
    end

    DECORATOR_RX = /@(tool|mcp\.tool|function_tool|ai_function|registerTool|server\.tool)\b/
    PATH_HINT_RX = %r{(?:^|/)(?:tools?|mcp|agents?|handlers?)/}i

    HTTP_CALLS = [
      /\brequests\.(get|post|put|patch|delete|head|request)\s*\(\s*([^)]+)/,
      /\bhttpx\.(get|post|put|patch|delete|head|stream|request)\s*\(\s*([^)]+)/,
      /\burllib\.request\.urlopen\s*\(\s*([^)]+)/,
      /\bfetch\s*\(\s*([^)]+)/,
      /\baxios\.(get|post|put|patch|delete|head|request)\s*\(\s*([^)]+)/,
      /\bhttp\.(Get|Post|NewRequest)\s*\(\s*([^)]+)/,
    ]

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless RuleContext.code_path?(path)
      return [] of Finding if RuleContext.test_path?(path)
      in_tool_path = !!PATH_HINT_RX.match(path)
      results = [] of Finding
      lines = source.lines
      decorator_pending = false
      lines.each_with_index do |line, i|
        if line =~ DECORATOR_RX
          decorator_pending = true
          next
        end
        in_tool_fn = in_tool_path || decorator_pending
        next if RuleContext.comment_only?(line)
        # reset pending after non-blank non-comment-non-decorator line
        HTTP_CALLS.each do |rx|
          next unless m = line.match(rx)
          args = m[-1]
          # Literal URL like "https://x/…" → safe.
          next if args =~ /\A\s*["'][^"']*["']\s*[,)\s]/
          next unless in_tool_fn
          results << finding(source, path, i + 1, m.begin(0) || 0,
            "Tool handler outbound call with non-literal URL — potential exfil")
          break
        end
        decorator_pending = false if line.strip != "" && line !~ DECORATOR_RX
      end
      results
    end
  end
end
