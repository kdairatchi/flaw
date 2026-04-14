require "./rule"
require "./context"

module Flaw
  # FLAW130 — hardcoded font-family outside token file. Typography drift.
  class FontFamilyDrift < Rule
    def id : String
      "FLAW130"
    end

    def title : String
      "Hardcoded font-family outside token file"
    end

    def default_severity : Severity
      Severity::Low
    end

    def tag : String
      "design"
    end

    def description : String
      <<-DESC
      A font-family declaration hardcodes a specific family name instead
      of referencing a CSS variable / design token. Typography drift
      produces inconsistent brand expression and makes theme swaps
      impossible. Move the family into the token set and reference via
      var(--font-*).
      DESC
    end

    EXTS       = %w(.css .scss .sass .less .vue .svelte)
    TOKEN_FILE = %r{(tokens?|theme|palette|colou?rs?|design[_\-]?system|fonts?|typography|tailwind\.config)\.(css|scss|sass|less|ts|tsx|js|mjs|cjs|json|yaml|yml)$}i
    RX         = /font-family\s*:\s*([^;{}\n]+)/i

    GENERIC = %w(inherit initial unset revert serif sans-serif monospace cursive fantasy system-ui ui-serif ui-sans-serif ui-monospace ui-rounded -apple-system BlinkMacSystemFont)

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless EXTS.any? { |ext| path.ends_with?(ext) }
      return [] of Finding if RuleContext.test_path?(path)
      return [] of Finding if TOKEN_FILE.match(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        if m = line.match(RX)
          rhs = m[1].strip
          next if rhs.starts_with?("var(")
          # Split on commas, strip quotes/whitespace, check if every token is generic.
          parts = rhs.split(',').map { |p| p.strip.strip('"').strip('\'').strip }
          all_generic = parts.all? { |p| GENERIC.includes?(p) || GENERIC.any? { |g| g.downcase == p.downcase } }
          next if all_generic
          # Find first non-generic name for the message.
          name = parts.find { |p| !GENERIC.any? { |g| g.downcase == p.downcase } } || rhs
          results << finding(source, path, idx, m.begin(0) || 0,
            "Hardcoded font-family '#{name}' — move to a typography token")
        end
      end
      results
    end
  end
end
