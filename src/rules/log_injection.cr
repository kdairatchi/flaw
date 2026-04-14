require "./rule"
require "./context"

module Flaw
  # FLAW124 — User input concatenated into log statements (CRLF log forging).
  class LogInjection < Rule
    def id : String
      "FLAW124"
    end

    def title : String
      "Log injection"
    end

    def default_severity : Severity
      Severity::Low
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      Writing raw user input into log messages lets an attacker inject
      CRLF sequences to forge log entries, poison log aggregators, or
      break JSON log parsers. Use structured logging and pass untrusted
      values as fields, not format args.
      DESC
    end

    # Python: logger.info("...".format / f"..." / concat) with request/params
    PY_LOG = /log(?:ger)?\.(?:debug|info|warn|warning|error|critical|exception)\s*\(/
    JS_LOG = /(?:console\.(?:log|warn|error|info|debug)|logger\.\w+)\s*\(/
    RB_LOG = /(?:Rails\.logger|logger)\.\w+\s*\(/

    TAINT_PY        = /(?:req\.|request\.|flask\.request|\bparams\b|\bg\.|\bsession\.|\bbody\b|\bquery\b)/
    TAINT_JS        = /\$\{\s*(?:req\.|request\.|params|body|query|userInput)/
    TAINT_JS_CONCAT = /\+\s*(?:req\.|request\.|params|body|query|userInput)/
    TAINT_RB        = /#\{\s*(?:params\[|request\.|session\[|body)/

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless RuleContext.code_path?(path)
      return [] of Finding if RuleContext.test_path?(path)
      results = [] of Finding
      is_py = path.ends_with?(".py")
      is_js = %w(.js .jsx .ts .tsx .mjs .cjs).any? { |e| path.ends_with?(e) }
      is_rb = path.ends_with?(".rb") || path.ends_with?(".cr")
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        matched = false
        col = 0
        if is_py && (m = line.match(PY_LOG))
          if line =~ TAINT_PY && (line.includes?("f\"") || line.includes?("f'") || line.includes?(".format(") || line.includes?(" + ") || line.includes?("%"))
            matched = true
            col = m.begin(0) || 0
          end
        end
        if !matched && is_js && (m = line.match(JS_LOG))
          if line =~ TAINT_JS || line =~ TAINT_JS_CONCAT
            matched = true
            col = m.begin(0) || 0
          end
        end
        if !matched && is_rb && (m = line.match(RB_LOG))
          if line =~ TAINT_RB
            matched = true
            col = m.begin(0) || 0
          end
        end
        if matched
          results << finding(source, path, idx, col,
            "User input concatenated into log — CRLF log forging risk; use structured logging")
        end
      end
      results
    end
  end
end
