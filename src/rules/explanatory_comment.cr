require "./rule"

module Flaw
  # FLAW100 — AI-slop tell: narration-style comments explaining obvious code.
  # Typical of pasted LLM output: "This function does X", "Here we loop",
  # "Now we check if Y". Real engineers rarely write these; well-named
  # identifiers already carry the intent.
  class ExplanatoryComment < Rule
    def id : String
      "FLAW100"
    end

    def title : String
      "Explanatory narration comment (AI-slop tell)"
    end

    def default_severity : Severity
      Severity::Low
    end

    def tag : String
      "ai-slop"
    end

    def description : String
      <<-DESC
      Matches comments that start with LLM-typical explainer phrases
      ("This function...", "Here we...", "Now we...", "First, we...",
      "The purpose of this...", "Note that..."). These comments restate
      the code rather than explain the *why* behind it, and are a strong
      signal of unedited AI-generated output.
      DESC
    end

    LEADERS = [
      /^\s*#\s*(This (function|method|class|module|code|block|loop|line|variable|test))\b/i,
      /^\s*#\s*(Here we|Here's|Now we|First,? we|Next,? we|Then we|Finally,? we|We will|We'll)\b/i,
      /^\s*#\s*(The purpose of (this|the)|The following|Note that|Please note|Keep in mind)\b/i,
      /^\s*#\s*(Initialize the|Create (a|the) new|Set (a|the|up) |Loop through|Iterate over|Check if)\b/i,
    ]

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        LEADERS.each do |re|
          if m = line.match(re)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Explanatory narration comment — delete it, or rewrite to explain *why* not *what*")
            break
          end
        end
      end
      results
    end
  end
end
