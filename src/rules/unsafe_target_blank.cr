require "./rule"
require "./context"

module Flaw
  # FLAW117 — target="_blank" without rel="noopener". Allows the opened page
  # to navigate window.opener — reverse-tabnabbing.
  class UnsafeTargetBlank < Rule
    def id : String
      "FLAW117"
    end

    def title : String
      "target=\"_blank\" without rel=\"noopener\""
    end

    def default_severity : Severity
      Severity::Low
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      An anchor/area/form opens in a new tab via target="_blank" but does not
      set rel="noopener" (or noreferrer). The opened document can navigate
      window.opener — reverse tabnabbing. Add rel="noopener noreferrer".
      DESC
    end

    ALL_TEMPLATE_EXTS = %w(.html .htm .jsx .tsx .vue .svelte .astro .erb .ecr .hbs .liquid .php)
    TAG_RX            = /<(?:a|area|form)\b[^>]*\btarget\s*=\s*["']?_blank["']?[^>]*>/i
    JSX_BRACE_RX      = /target\s*=\s*\{\s*["']_blank["']\s*\}/i

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless applicable?(path)
      return [] of Finding if RuleContext.test_path?(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        if m = line.match(TAG_RX)
          tag = m[0]
          unless tag =~ /\brel\s*=\s*["'][^"']*(?:noopener|noreferrer)[^"']*["']/i
            results << finding(source, path, idx, m.begin(0) || 0,
              "target=\"_blank\" without rel=\"noopener\" — reverse-tabnabbing risk")
          end
        elsif m = line.match(JSX_BRACE_RX)
          unless line =~ /\brel\s*=\s*[\{"'][^}"']*(?:noopener|noreferrer)/i
            results << finding(source, path, idx, m.begin(0) || 0,
              "target=\"_blank\" without rel=\"noopener\" — reverse-tabnabbing risk")
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
