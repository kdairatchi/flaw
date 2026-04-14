require "./rule"
require "./context"

module Flaw
  # FLAW119 — overuse of !important. Specificity-war signal.
  class ImportantOveruse < Rule
    def id : String
      "FLAW119"
    end

    def title : String
      "Overuse of !important in stylesheet"
    end

    def default_severity : Severity
      Severity::Info
    end

    def tag : String
      "design"
    end

    def description : String
      <<-DESC
      This stylesheet uses !important more than five times. That usually
      means selectors are fighting each other — refactor specificity or
      restructure the cascade instead of forcing overrides.
      DESC
    end

    EXTS = %w(.css .scss .sass .less .vue .svelte)

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless EXTS.any? { |e| path.ends_with?(e) }
      return [] of Finding if RuleContext.test_path?(path)
      return [] of Finding if RuleContext.doc_path?(path)
      count = 0
      first_line = 0
      first_col = 0
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        line.scan(/!important/i) do |m|
          count += 1
          if first_line == 0
            first_line = idx
            first_col = m.begin(0) || 0
          end
        end
      end
      return [] of Finding if count <= 5
      [finding(source, path, first_line, first_col,
        "#{count} uses of !important in this file — specificity war; refactor selectors")]
    end
  end
end
