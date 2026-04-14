require "./rule"
require "./context"

module Flaw
  # FLAW128 — click handler on non-interactive element. WCAG 2.1.1 Keyboard.
  class ClickNonInteractive < Rule
    def id : String
      "FLAW128"
    end

    def title : String
      "Click handler on non-interactive element"
    end

    def default_severity : Severity
      Severity::Low
    end

    def tag : String
      "a11y"
    end

    def description : String
      <<-DESC
      A click handler is attached to a <div>, <span>, or similar non-
      interactive element without a keyboard equivalent. Keyboard users
      can't reach or activate the control. Use a <button>, or add both
      role="button" and a tabindex plus a keydown handler. WCAG 2.1.1.
      DESC
    end

    EXTS      = %w(.jsx .tsx .vue .svelte .html .htm .astro .erb .ecr)
    TAGS      = "div|span|li|p|section|article|header|footer|main|aside"
    JSX_RX    = /<(#{TAGS})\b([^>]*\bonClick\s*=[^>]*)>/i
    VUE_RX    = /<(#{TAGS})\b([^>]*(?:@click\s*=|v-on:click\s*=)[^>]*)>/i
    SVELTE_RX = /<(#{TAGS})\b([^>]*\bon:click\s*=[^>]*)>/i
    HTML_RX   = /<(#{TAGS})\b([^>]*\bonclick\s*=[^>]*)>/i

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless EXTS.any? { |ext| path.ends_with?(ext) }
      return [] of Finding if RuleContext.test_path?(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        [JSX_RX, VUE_RX, SVELTE_RX, HTML_RX].each do |rx|
          if m = line.match(rx)
            tag_name = m[1]
            attrs = m[2]
            # Skip when developer added role="button" AND a tabindex.
            has_role = attrs.includes?(%(role="button")) || attrs.includes?(%(role='button'))
            has_tabindex = attrs =~ /\btab[Ii]ndex\b/
            next if has_role && has_tabindex
            results << finding(source, path, idx, m.begin(0) || 0,
              "Click handler on <#{tag_name}> without keyboard equivalent — keyboard users excluded (WCAG 2.1.1)")
            break
          end
        end
      end
      results
    end
  end
end
