require "./rule"
require "./context"

module Flaw
  # FLAW122 — Server-side template injection.
  class Ssti < Rule
    def id : String
      "FLAW122"
    end

    def title : String
      "Server-side template injection"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      Rendering a template from a string built with interpolation lets an
      attacker inject template directives that execute in the engine's
      sandbox — often leading to RCE. Pass untrusted data as context
      variables, never as part of the template source.
      DESC
    end

    EXT = %w(.py .rb .cr .js .jsx .ts .tsx .mjs .cjs)

    PY_RENDER_STR = /render_template_string\s*\(([^)]*)/
    PY_TEMPLATE   = /Template\s*\([^)]*\)\s*\.\s*render\s*\(/
    JINJA_FROM    = /Jinja2?\s*\.\s*from_string\s*\(([^)]*)/
    RUBY_ERB      = /ERB\.new\s*\(([^)]*)/
    HBS_COMPILE   = /(?:H|h)andlebars\s*\.\s*compile\s*\(([^)]*)/

    TAINT_TOKENS = ["+", "\#{", "${", "{{", "%s", ".format(", "f\"", "f'"]

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless EXT.any? { |e| path.ends_with?(e) }
      return [] of Finding if RuleContext.test_path?(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        [PY_RENDER_STR, JINJA_FROM, RUBY_ERB, HBS_COMPILE].each do |rx|
          if m = line.match(rx)
            arg = m[1]
            if tainted?(arg)
              results << finding(source, path, idx, m.begin(0) || 0,
                "Template render with interpolated input — SSTI risk, pass data via context not string")
              break
            end
          end
        end
        if m = line.match(PY_TEMPLATE)
          # Template("...").render(...) — flag when template source has interpolation
          head = line[0, m.end(0)]
          if tainted?(head)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Template render with interpolated input — SSTI risk, pass data via context not string")
          end
        end
      end
      results
    end

    private def tainted?(s : String) : Bool
      TAINT_TOKENS.any? { |t| s.includes?(t) }
    end
  end
end
