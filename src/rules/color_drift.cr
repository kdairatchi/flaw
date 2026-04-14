require "./rule"
require "./context"

module Flaw
  # FLAW106 — color token drift. Raw hex colors in stylesheets/JSX outside
  # of declared token files (tokens.css, theme.ts, tailwind config). Also
  # flags near-duplicate hexes — accidental dupes like #0a0a0a vs #0b0b0b —
  # which indicate the palette wasn't audited.
  class ColorDrift < Rule
    def id : String
      "FLAW106"
    end

    def title : String
      "Raw color literal outside token file"
    end

    def default_severity : Severity
      Severity::Low
    end

    def tag : String
      "design"
    end

    def description : String
      <<-DESC
      A 3/6/8-digit hex color or rgb()/rgba() call appears in source outside
      of a declared design-token file. Palette drift produces a codebase with
      dozens of "almost the same" shades. Move the color into the token set
      (tokens.css, theme.ts, tailwind.config) and reference it by name.
      DESC
    end

    TOKEN_FILE = %r{(tokens?|theme|palette|colou?rs?|design[_\-]?system|tailwind\.config)\.(css|scss|sass|less|ts|tsx|js|mjs|cjs|json|yaml|yml)$}i
    HEX_RX     = /(?<![\w#])#([0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})\b/
    RGB_RX     = /\brgba?\(\s*\d+\s*,\s*\d+\s*,\s*\d+(\s*,\s*[\d.]+)?\s*\)/
    # Black/white/transparent variants are fine everywhere.
    TRIVIAL = Set{"#000", "#fff", "#000000", "#ffffff", "#0000", "#ffffffff"}

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless applicable?(path)
      return [] of Finding if TOKEN_FILE.match(path)
      return [] of Finding if RuleContext.doc_path?(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        # Skip CSS custom-property declarations themselves; they are the
        # token sink even if the file is not named tokens.css.
        next if line =~ /^\s*--[a-zA-Z0-9_-]+\s*:/
        line.scan(HEX_RX) do |m|
          hex = m[0].downcase
          next if TRIVIAL.includes?(hex)
          col = line.index(hex) || 0
          results << finding(source, path, idx, col,
            "Raw hex '#{hex}' — move to a design token and reference by name")
        end
        if m = line.match(RGB_RX)
          results << finding(source, path, idx, m.begin(0) || 0,
            "Raw rgb()/rgba() literal — move to a design token and reference by name")
        end
      end
      results
    end

    private def applicable?(path : String) : Bool
      return true if RuleContext.web_path?(path)
      return true if path =~ /\.(jsx|tsx|vue|svelte|astro|html)$/
      return true if path =~ /tailwind\.config\.(js|ts|mjs|cjs)$/
      false
    end
  end
end
