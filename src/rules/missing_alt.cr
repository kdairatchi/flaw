require "./rule"
require "./context"

module Flaw
  # FLAW118 — <img> without alt attribute. WCAG 1.1.1 non-text content.
  class MissingAlt < Rule
    def id : String
      "FLAW118"
    end

    def title : String
      "<img> without alt attribute"
    end

    def default_severity : Severity
      Severity::Low
    end

    def tag : String
      "a11y"
    end

    def description : String
      <<-DESC
      An <img> or <input type="image"> element has no alt attribute. Screen
      readers announce the filename or skip the element. Add alt="" for
      decorative images or alt="description" for meaningful ones (WCAG 1.1.1).
      DESC
    end

    ALL_TEMPLATE_EXTS = %w(.html .htm .jsx .tsx .vue .svelte .astro .erb .ecr .hbs .liquid .php)
    IMG_RX            = /<img\b(?![^>]*\balt\s*=)[^>]*\/?>/i
    INPUT_IMG_RX      = /<input\b[^>]*\btype\s*=\s*["']image["'][^>]*>/i

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless applicable?(path)
      return [] of Finding if RuleContext.test_path?(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        if m = line.match(IMG_RX)
          results << finding(source, path, idx, m.begin(0) || 0,
            "<img> without alt attribute — required for screen readers (WCAG 1.1.1)")
        end
        if m = line.match(INPUT_IMG_RX)
          tag = m[0]
          unless tag =~ /\balt\s*=/i
            results << finding(source, path, idx, m.begin(0) || 0,
              "<img> without alt attribute — required for screen readers (WCAG 1.1.1)")
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
