require "./rule"
require "./context"

module Flaw
  # FLAW109 — WCAG AA contrast fail. When a CSS rule block declares both
  # `color:` and `background(-color)?:` with hex literals, compute the
  # WCAG 2.x contrast ratio. Normal body text needs >= 4.5:1; below that
  # the pair is flagged. rgb()/rgba()/named colors are ignored — keeps
  # this a cheap static check, no colour-name table to drift.
  class ContrastFail < Rule
    def id : String
      "FLAW109"
    end

    def title : String
      "Low color contrast (WCAG AA fail)"
    end

    def default_severity : Severity
      Severity::Low
    end

    def tag : String
      "design"
    end

    def description : String
      <<-DESC
      Foreground/background hex pair in the same CSS rule fails WCAG AA
      (ratio < 4.5:1 for normal text). Pick a darker foreground or lighter
      background so the text is legible to low-vision users.
      DESC
    end

    HEX_RX = /#([0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})\b/

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless RuleContext.web_path?(path)
      return [] of Finding if RuleContext.doc_path?(path)

      results = [] of Finding
      lines = source.split('\n')
      depth = 0
      block_start = -1
      block_lines = [] of Tuple(Int32, String) # (1-based line no, line)

      lines.each_with_index do |line, i|
        lineno = i + 1
        opened_here = false
        line.each_char do |c|
          if c == '{'
            if depth == 0
              block_start = lineno
              block_lines = [] of Tuple(Int32, String)
              opened_here = true
            end
            depth += 1
          elsif c == '}'
            depth -= 1
            if depth == 0 && block_start > 0
              block_lines << {lineno, line} unless block_lines.any? { |(ln, _)| ln == lineno }
              if f = analyze_block(source, path, block_lines)
                results << f
              end
              block_start = -1
              block_lines = [] of Tuple(Int32, String)
              opened_here = false
            end
            depth = 0 if depth < 0
          end
        end
        if depth > 0 || opened_here
          block_lines << {lineno, line} unless block_lines.any? { |(ln, _)| ln == lineno }
        end
      end

      results
    end

    private def analyze_block(source, path, block_lines) : Finding?
      fg_hex = nil.as(String?)
      fg_line = 0
      fg_col = 0
      bg_hex = nil.as(String?)

      block_lines.each do |(lineno, line)|
        stripped = line.strip
        next if stripped.starts_with?("//") || stripped.starts_with?("/*") || stripped.starts_with?('*')

        if fg_hex.nil? && (m = line.match(/(?<![\-\w])color\s*:\s*(#[0-9a-fA-F]{3,8})/))
          if hex = m[1]?
            if norm = normalize_hex(hex)
              fg_hex = norm
              fg_line = lineno
              fg_col = line.index("color") || 0
            end
          end
        end

        if bg_hex.nil? && (m = line.match(/background(?:-color)?\s*:\s*[^;]*?(#[0-9a-fA-F]{3,8})/))
          if hex = m[1]?
            if norm = normalize_hex(hex)
              bg_hex = norm
            end
          end
        end
      end

      return nil unless fg_hex && bg_hex
      ratio = contrast_ratio(fg_hex, bg_hex)
      return nil if ratio >= 4.5
      finding(source, path, fg_line, fg_col,
        "Contrast #{ratio.round(2)}:1 between #{fg_hex} and #{bg_hex} — WCAG AA requires >=4.5:1 for normal text")
    end

    private def normalize_hex(hex : String) : String?
      h = hex.lchop('#').downcase
      case h.size
      when 3
        "##{h[0]}#{h[0]}#{h[1]}#{h[1]}#{h[2]}#{h[2]}"
      when 6
        "##{h}"
      when 8
        "##{h[0, 6]}"
      else
        nil
      end
    end

    private def contrast_ratio(fg : String, bg : String) : Float64
      l1 = luminance(fg)
      l2 = luminance(bg)
      lighter = l1 > l2 ? l1 : l2
      darker = l1 > l2 ? l2 : l1
      (lighter + 0.05) / (darker + 0.05)
    end

    private def luminance(hex : String) : Float64
      h = hex.lchop('#')
      r = h[0, 2].to_i(16)
      g = h[2, 2].to_i(16)
      b = h[4, 2].to_i(16)
      0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
    end

    private def channel(c : Int32) : Float64
      sc = c / 255.0
      sc <= 0.03928 ? sc / 12.92 : ((sc + 0.055) / 1.055) ** 2.4
    end
  end
end
