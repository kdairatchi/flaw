require "./rule"
require "./context"

module Flaw
  # FLAW127 — <html> without lang attribute. WCAG 3.1.1 Language of Page.
  class HtmlNoLang < Rule
    def id : String
      "FLAW127"
    end

    def title : String
      "<html> without lang attribute"
    end

    def default_severity : Severity
      Severity::Low
    end

    def tag : String
      "a11y"
    end

    def description : String
      <<-DESC
      The root <html> element has no lang attribute. Screen readers can't
      choose the correct pronunciation dictionary, and translation tools
      can't detect the page language. Add lang="en" (or appropriate BCP-47
      tag). WCAG 3.1.1 Language of Page.
      DESC
    end

    EXTS = %w(.html .htm .erb .ecr .hbs .liquid .php .vue .svelte .astro)
    RX   = /<html\b(?![^>]*\blang\s*=)[^>]*>/i

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless EXTS.any? { |ext| path.ends_with?(ext) }
      return [] of Finding if RuleContext.test_path?(path)
      return [] of Finding if RuleContext.doc_path?(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        if m = line.match(RX)
          results << finding(source, path, idx, m.begin(0) || 0,
            "<html> without lang attribute — screen readers can't announce pronunciation (WCAG 3.1.1)")
        end
      end
      results
    end
  end
end
