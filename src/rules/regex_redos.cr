require "./rule"

module Flaw
  # FLAW017 — Regex with nested quantifiers and alternation. Catastrophic
  # backtracking candidate. Only a heuristic — true ReDoS requires an engine
  # simulation, but the shape (a+)+, (a|a)+, (a*)* is a strong tell.
  class RegexRedos < Rule
    def id : String
      "FLAW017"
    end

    def title : String
      "Regex pattern with nested quantifiers (ReDoS risk)"
    end

    def default_severity : Severity
      Severity::Low
    end

    def description : String
      <<-DESC
      A regex literal contains a nested quantifier (e.g. `(a+)+`, `(a*)*`,
      `(a|a)+`). Against a crafted input this can take exponential time and
      DoS the process. Rewrite to avoid the nesting or use an atomic group
      workaround; PCRE-style atomic groups are not available in Crystal so
      prefer possessive matching via greedy tokens with disjoint alphabets.
      DESC
    end

    # /(<quant>)<outer_quant>/ where quant contains + or *
    PATTERN = /\/[^\/\n]*\([^)]*[+*][^)]*\)[+*][^\/\n]*\//

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        if m = line.match(PATTERN)
          results << finding(source, path, idx, m.begin(0) || 0,
            "Nested quantifier in regex — potential catastrophic backtracking")
        end
      end
      results
    end
  end
end
