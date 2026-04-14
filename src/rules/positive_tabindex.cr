require "./rule"
require "./context"

module Flaw
  # FLAW120 — positive tabindex. Breaks natural tab order (WCAG 2.4.3).
  class PositiveTabindex < Rule
    def id : String
      "FLAW120"
    end

    def title : String
      "Positive tabindex breaks tab order"
    end

    def default_severity : Severity
      Severity::Low
    end

    def tag : String
      "a11y"
    end

    def description : String
      <<-DESC
      A tabindex greater than 0 forces this element out of natural DOM order
      in keyboard navigation, breaking focus flow for screen-reader users.
      Use tabindex="0" (focusable in order) or tabindex="-1" (programmatic
      focus only). WCAG 2.4.3 Focus Order.
      DESC
    end

    ALL_TEMPLATE_EXTS = %w(.html .htm .jsx .tsx .vue .svelte .astro .erb .ecr .hbs .liquid .php)
    HTML_RX           = /\btabindex\s*=\s*["']?([1-9]\d*)["']?/i
    JSX_BRACE_RX      = /\btabIndex\s*=\s*\{\s*([1-9]\d*)\s*\}/
    JSX_STR_RX        = /\btabIndex\s*=\s*["']([1-9]\d*)["']/

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless applicable?(path)
      return [] of Finding if RuleContext.test_path?(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        [HTML_RX, JSX_BRACE_RX, JSX_STR_RX].each do |rx|
          if m = line.match(rx)
            n = m[1]
            results << finding(source, path, idx, m.begin(0) || 0,
              "Positive tabindex #{n} — breaks natural tab order (WCAG 2.4.3)")
            break
          end
        end
      end
      results
    end

    private def applicable?(path : String) : Bool
      return true if path.ends_with?(".md")
      ALL_TEMPLATE_EXTS.any? { |ext| path.ends_with?(ext) }
    end
  end
end
