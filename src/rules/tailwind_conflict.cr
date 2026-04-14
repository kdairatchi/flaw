require "./rule"
require "./context"

module Flaw
  # FLAW121 — conflicting Tailwind utilities on the same element. Only the
  # last one applied to the cascade wins; the others are dead bytes.
  class TailwindConflict < Rule
    def id : String
      "FLAW121"
    end

    def title : String
      "Conflicting Tailwind utilities on same element"
    end

    def default_severity : Severity
      Severity::Low
    end

    def tag : String
      "design"
    end

    def description : String
      <<-DESC
      Multiple Tailwind utilities from the same family (display, text size,
      padding, margin) appear on a single element. Only one survives the
      cascade; the rest are dead code. Pick one intentional utility.
      DESC
    end

    ALL_TEMPLATE_EXTS = %w(.html .htm .jsx .tsx .vue .svelte .astro .erb .ecr .hbs .liquid .php)
    CLASS_RX          = /(?:class|className)\s*=\s*["']([^"']+)["']/
    DISPLAY_TOKENS    = Set{"block", "inline", "inline-block", "flex", "inline-flex", "grid", "inline-grid", "hidden", "contents", "table"}
    TEXT_SIZES        = Set{"xs", "sm", "base", "lg", "xl", "2xl", "3xl", "4xl", "5xl", "6xl"}

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless ALL_TEMPLATE_EXTS.any? { |e| path.ends_with?(e) }
      return [] of Finding if RuleContext.test_path?(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        line.scan(CLASS_RX) do |m|
          classes = m[1].split(/\s+/).reject(&.empty?)
          col = line.index(m[0]) || 0
          if conflict = find_conflict(classes)
            results << finding(source, path, idx, col,
              "Conflicting Tailwind classes: #{conflict} — only one will apply")
          end
        end
      end
      results
    end

    private def find_conflict(classes : Array(String)) : String?
      displays = classes.select { |c| DISPLAY_TOKENS.includes?(c) }
      return displays.join(", ") if displays.size > 1

      text_sizes = [] of String
      classes.each do |c|
        if m = c.match(/\Atext-(xs|sm|base|lg|xl|2xl|3xl|4xl|5xl|6xl)\z/)
          text_sizes << c if TEXT_SIZES.includes?(m[1])
        end
      end
      if text_sizes.map { |c| c.split('-', 2)[1] }.uniq.size > 1
        return text_sizes.join(", ")
      end

      # Padding / margin axis families
      %w(p px py m mx my).each do |prefix|
        rx = /\A#{Regex.escape(prefix)}-(\d+(?:\.\d+)?|px)\z/
        matched = classes.select { |c| c =~ rx }
        values = matched.map { |c| c.split('-', 2)[1] }.uniq
        if values.size > 1
          return matched.join(", ")
        end
      end

      nil
    end
  end
end
