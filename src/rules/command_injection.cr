require "./rule"

module Flaw
  # FLAW001 — AST-backed. Fires when `system`, backticks, or `Process.run`
  # receive an argument that is a `Crystal::StringInterpolation` (i.e., a
  # double-quoted string with `#{…}`). Passing argv as an array to
  # `Process.run` does not parse through a shell and does not fire.
  class CommandInjection < AstRule
    def id : String
      "FLAW001"
    end

    def title : String
      "OS command built from interpolated input"
    end

    def default_severity : Severity
      Severity::Critical
    end

    def description : String
      <<-DESC
      A call to `system`, `` ` `` (backticks), or `Process.run` had its command
      string built by string interpolation. If any interpolated value originates
      from user input, this is a command injection sink. Pass arguments as an
      argv array to `Process.run` instead.
      DESC
    end

    SHELL_CALLS = {"system", "`", "exec"}

    def visit(node, source : String, path : String, findings : Array(Finding)) : Nil
      return unless node.is_a?(Crystal::Call)
      return unless shelly?(node)
      first = node.args.first?
      return unless first.is_a?(Crystal::StringInterpolation)
      return if all_sanitized?(first)
      line = node.location.try(&.line_number) || 1
      col = node.location.try(&.column_number) || 0
      findings << finding(source, path, line, col - 1,
        "Command built via string interpolation — pass Process.run an argv array or taint-check the inputs")
    end

    # Every interpolated expression is a literal or a call that can't
    # produce shell metachars (numeric coercions). Skip.
    private def all_sanitized?(interp : Crystal::StringInterpolation) : Bool
      interp.expressions.all? do |e|
        case e
        when Crystal::StringLiteral, Crystal::NumberLiteral
          true
        when Crystal::Call
          Taint.sanitized_call?(e)
        else
          false
        end
      end
    end

    private def shelly?(node : Crystal::Call) : Bool
      return true if SHELL_CALLS.includes?(node.name)
      if node.name == "run" && (obj = node.obj)
        return true if obj.to_s == "Process"
      end
      false
    end
  end
end
