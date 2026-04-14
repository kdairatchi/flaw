require "./rule"
require "./context"

module Flaw
  # FLAW113 — DOM XSS sinks in front-end code.
  class DomXssSink < Rule
    def id : String
      "FLAW113"
    end

    def title : String
      "DOM XSS sink"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      Writing to innerHTML/outerHTML/document.write/insertAdjacentHTML or
      framework equivalents (dangerouslySetInnerHTML, v-html, {@html ...})
      interprets the assigned value as HTML. Unless the source is a static
      literal under your control, it's an XSS vector. Prefer textContent,
      createElement, or a sanitizer (DOMPurify).
      DESC
    end

    EXT = %w(.js .jsx .ts .tsx .html .vue .svelte)

    INNER_RX  = /(\.innerHTML|\.outerHTML)\s*=\s*(.*)$/
    DOC_WRITE = /document\.write\s*\(/
    INS_ADJ   = /\.insertAdjacentHTML\s*\(/
    REACT_RX  = /dangerouslySetInnerHTML\s*[:=]/
    VUE_RX    = /\bv-html\s*=/
    SVELTE_RX = /\{@html\s+/

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless EXT.any? { |e| path.ends_with?(e) }
      return [] of Finding if RuleContext.test_path?(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        if m = line.match(INNER_RX)
          rhs = m[2]
          stripped = RuleContext.strip_strings_and_comments(rhs).strip.sub(/;?\s*$/, "")
          unless stripped.empty?
            results << finding(source, path, idx, m.begin(0) || 0,
              "DOM XSS sink — sanitize or use textContent/createElement")
            next
          end
        end
        [DOC_WRITE, INS_ADJ, REACT_RX, VUE_RX, SVELTE_RX].each do |rx|
          if m = line.match(rx)
            results << finding(source, path, idx, m.begin(0) || 0,
              "DOM XSS sink — sanitize or use textContent/createElement")
            break
          end
        end
      end
      results
    end
  end
end
