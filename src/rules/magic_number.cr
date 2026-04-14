require "./rule"
require "./context"

module Flaw
  # FLAW110 — unnamed numeric literal in code. Numbers big enough to carry
  # meaning (>=3 digits) or awkward non-trivial values hiding inside
  # comparisons and arithmetic should be named constants.
  class MagicNumber < Rule
    def id : String
      "FLAW110"
    end

    def title : String
      "Magic number — name it as a constant"
    end

    def default_severity : Severity
      Severity::Info
    end

    def tag : String
      "hygiene"
    end

    def description : String
      <<-DESC
      A numeric literal with three or more digits appears inside a
      comparison or arithmetic expression without being bound to a
      named constant. Extract it to a CONST so the value's meaning
      lives next to its name.
      DESC
    end

    TRIVIAL = Set{
      "0", "1", "-1", "2", "10", "100", "1000", "10000",
      "60", "24", "3600", "86400", "7", "30", "31", "365", "366",
      # HTTP status codes
      "200", "201", "202", "204", "301", "302", "304", "307", "308",
      "400", "401", "403", "404", "405", "409", "410", "422", "429",
      "500", "501", "502", "503", "504",
      # Common byte/bit sizes
      "128", "256", "512", "1024", "2048", "4096", "8192", "16384", "32768", "65536",
      # Common ports
      "80", "443", "8080", "8443", "3000", "5000", "8000", "22", "25",
    }
    NUMBER_RX = /(?<![\w.])(-?\d{3,})(?![\w.])/
    OP_RX     = /[+\-*\/%<>]|==|!=|<=|>=/
    CONST_LHS = /\b[A-Z_][A-Z0-9_]*\s*=/

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless RuleContext.code_path?(path)
      return [] of Finding if RuleContext.test_path?(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        # Skip constant assignments: CONST = 1234
        next if CONST_LHS.match(line)
        stripped = RuleContext.strip_strings_and_comments(line)
        next unless OP_RX.match(stripped)
        stripped.scan(NUMBER_RX) do |m|
          num = m[1]
          next if TRIVIAL.includes?(num)
          col = stripped.index(num) || 0
          results << finding(source, path, idx, col,
            "Magic number #{num} — name it as a const for readability")
        end
      end
      results
    end
  end
end
