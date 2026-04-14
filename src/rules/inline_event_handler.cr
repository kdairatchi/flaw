require "./rule"
require "./context"

module Flaw
  # FLAW129 — inline on*= event handler. Blocks CSP script-src and widens XSS.
  class InlineEventHandler < Rule
    def id : String
      "FLAW129"
    end

    def title : String
      "Inline event handler attribute"
    end

    def default_severity : Severity
      Severity::Low
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      Inline event handler attributes (onclick=, onload=, etc.) force a
      relaxed Content-Security-Policy — either 'unsafe-inline' on
      script-src or explicit unsafe-hashes. Any injected HTML can then
      execute script. Move handlers to addEventListener in a separate
      file and tighten CSP.
      DESC
    end

    EXTS = %w(.html .htm .erb .ecr .hbs .liquid .php)
    RX   = /\bon(click|load|error|mouseover|mouseout|submit|change|focus|blur|input|keydown|keyup|keypress)\s*=\s*["']/i

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless EXTS.any? { |ext| path.ends_with?(ext) }
      return [] of Finding if RuleContext.test_path?(path)
      return [] of Finding if RuleContext.doc_path?(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        if m = line.match(RX)
          ev = m[1]
          results << finding(source, path, idx, m.begin(0) || 0,
            "Inline on#{ev}= handler — blocks CSP script-src and widens XSS blast radius")
        end
      end
      results
    end
  end
end
