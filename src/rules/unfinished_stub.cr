require "./rule"

module Flaw
  # FLAW103 — AI-slop / unfinished stub left in source.
  class UnfinishedStub < Rule
    def id : String
      "FLAW103"
    end

    def title : String
      "Unfinished stub left in source"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def description : String
      <<-DESC
      A method body is `raise NotImplementedError`, `# TODO: implement`,
      `# implement this`, or consists of a `pending` return without a real
      implementation. Common AI-assistant scaffolding that ships to prod if
      not caught.
      DESC
    end

    def tag : String
      "ai-slop"
    end

    PATTERNS = [
      /\braise\s+NotImplementedError/,
      /#\s*TODO:?\s*implement\b/i,
      /#\s*implement (this|me)\b/i,
      /#\s*stub\b/i,
    ]

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        PATTERNS.each do |re|
          if m = line.match(re)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Unfinished stub — replace with a real implementation before shipping")
            break
          end
        end
      end
      results
    end
  end
end
