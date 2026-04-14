require "./rule"
require "./context"

module Flaw
  # FLAW133 — NoSQL injection sinks.
  class NoSqlInjection < Rule
    def id : String
      "FLAW133"
    end

    def title : String
      "NoSQL injection sink"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      $where / $function operators evaluate arbitrary JavaScript inside
      MongoDB. Passing user input into them is remote code execution.
      Passing non-literal query objects built from request data risks
      operator injection (e.g. {"$gt": ""} to bypass auth).
      DESC
    end

    EXT = %w(.js .jsx .ts .tsx .mjs .cjs .py)

    TAINT      = /(req\.|params|body|userInput|query)/
    WHERE_LINE = /\$where\s*:/
    FUNC_LINE  = /\$function\s*:/
    FIND_WHERE = /Mongo(?:DB)?\.\w+\.find\s*\(\s*\{[^}]*\$where/
    # Bounded alternative avoids .*? + char-class backtracking on long lines.
    DB_OP       = /\bdb\.\w+\.(?:find|update|delete)\s*\(\s*[^{)\n]{0,200}\b(?:req|params|body)\b/
    EVAL_MONGO  = /\beval\s*\([^)\n]{0,200}(?:MongoClient|MongoDB)/
    BATCH_RULES = [FIND_WHERE, DB_OP, EVAL_MONGO]

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless EXT.any? { |e| path.ends_with?(e) }
      return [] of Finding if RuleContext.test_path?(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        if (m = line.match(WHERE_LINE)) && line =~ TAINT
          results << finding(source, path, idx, m.begin(0) || 0,
            "NoSQL injection sink — $where/$function with user input or unparameterised query")
          next
        end
        if (m = line.match(FUNC_LINE)) && line =~ TAINT
          results << finding(source, path, idx, m.begin(0) || 0,
            "NoSQL injection sink — $where/$function with user input or unparameterised query")
          next
        end
        BATCH_RULES.each do |rx|
          if m = line.match(rx)
            results << finding(source, path, idx, m.begin(0) || 0,
              "NoSQL injection sink — $where/$function with user input or unparameterised query")
            break
          end
        end
      end
      results
    end
  end
end
