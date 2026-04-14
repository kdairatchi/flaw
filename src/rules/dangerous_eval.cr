require "./rule"
require "./context"

module Flaw
  # FLAW112 — dynamic code execution sinks across languages.
  class DangerousEval < Rule
    def id : String
      "FLAW112"
    end

    def title : String
      "Dynamic code execution sink"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      eval/exec/Function and similar sinks turn strings into executable code.
      If any byte of that string is attacker-influenced, it becomes RCE. Use
      explicit parsing, whitelists, or language-native dispatch instead.
      DESC
    end

    PY_PATTERNS = [
      {rx: /\beval\s*\(/, label: "eval("},
      {rx: /\bexec\s*\(/, label: "exec("},
      {rx: /compile\s*\([^)]+,\s*["']exec["']/, label: "compile(...,'exec')"},
    ]

    JS_PATTERNS = [
      {rx: /\beval\s*\(/, label: "eval("},
      {rx: /new\s+Function\s*\(/, label: "new Function("},
      {rx: /setTimeout\s*\(\s*["']/, label: "setTimeout(string)"},
      {rx: /setInterval\s*\(\s*["']/, label: "setInterval(string)"},
    ]

    RB_PATTERNS = [
      {rx: /\beval\s*\(/, label: "eval("},
      {rx: /instance_eval\s*[\(\s]/, label: "instance_eval"},
      {rx: /class_eval\s*[\(\s]/, label: "class_eval"},
      {rx: /\bsend\s*\(\s*params/, label: "send(params)"},
      {rx: /\bpublic_send\s*\(\s*params/, label: "public_send(params)"},
    ]

    PY_EXT = %w(.py)
    JS_EXT = %w(.js .jsx .ts .tsx .mjs .cjs)
    RB_EXT = %w(.rb .cr)

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding if RuleContext.test_path?(path) || RuleContext.doc_path?(path)
      patterns = if PY_EXT.any? { |e| path.ends_with?(e) }
                   PY_PATTERNS
                 elsif JS_EXT.any? { |e| path.ends_with?(e) }
                   JS_PATTERNS
                 elsif RB_EXT.any? { |e| path.ends_with?(e) }
                   RB_PATTERNS
                 else
                   return [] of Finding
                 end
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        patterns.each do |p|
          if m = line.match(p[:rx])
            results << finding(source, path, idx, m.begin(0) || 0,
              "Dynamic code execution sink (#{p[:label]}) — never feed user input here")
            break
          end
        end
      end
      results
    end
  end
end
