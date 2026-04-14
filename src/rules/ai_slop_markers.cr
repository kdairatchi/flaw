require "./rule"
require "./context"

module Flaw
  # FLAW108 — AI-generated tells that slipped into source: decorative emoji,
  # leaked Markdown code fences, placeholder identifiers, and sycophantic
  # comment openers. These are strong signals the file wasn't reviewed after
  # being pasted from an LLM.
  class AiSlopMarkers < Rule
    def id : String
      "FLAW108"
    end

    def title : String
      "AI slop marker in source"
    end

    def default_severity : Severity
      Severity::Low
    end

    def tag : String
      "ai-slop"
    end

    def description : String
      <<-DESC
      Source contains decorative emoji, leaked Markdown code fences,
      placeholder identifiers (foo/bar/do_something), or sycophantic
      openers ("Certainly!", "Sure!") — hallmarks of un-reviewed
      LLM output. Clean the code before committing.
      DESC
    end

    EMOJI_RX       = Regex.new("[\u{2705}\u{274C}\u{1F680}\u{26A1}\u{FE0F}\u{1F389}\u{1F525}\u{2728}\u{1F4DD}]")
    FENCE_RX       = /\A\s*```(python|crystal|cr|javascript|js|typescript|ts|ruby|rb|go|rust|rs)\s*\z/
    PLACEHOLDER_RX = /\b(def|fun|function|fn|class)\s+(foo|bar|baz|qux|my_func|example_func|do_something|process_data)\b/
    SYCOPHANT_RX   = /\b(Certainly!|Sure!|Absolutely!|Great question!)/

    FENCE_EXTS = %w(.cr .py .js .ts .rb .go .rs)

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless RuleContext.code_path?(path)
      return [] of Finding if RuleContext.test_path?(path)
      fence_eligible = FENCE_EXTS.any? { |ext| path.ends_with?(ext) }
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        if m = line.match(EMOJI_RX)
          results << finding(source, path, idx, m.begin(0) || 0,
            "Decorative emoji in source — drop it")
        end
        if fence_eligible && FENCE_RX.match(line)
          results << finding(source, path, idx, 0,
            "Leaked Markdown code fence inside source file")
        end
        if m = line.match(PLACEHOLDER_RX)
          results << finding(source, path, idx, m.begin(0) || 0,
            "Placeholder identifier '#{m[2]}' — rename to something meaningful")
        end
        if RuleContext.comment_only?(line)
          if m = line.match(SYCOPHANT_RX)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Sycophantic LLM opener in comment — remove")
          end
        end
      end
      results
    end
  end
end
