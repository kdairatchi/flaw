require "./rule"

module Flaw
  # FLAW003 — AST-backed. Fires when a `db.query` / `db.exec` / `db.scalar` /
  # `db.query_one` / `db.query_all` call receives a first argument that is a
  # `Crystal::StringInterpolation` whose literal parts contain SQL keywords,
  # OR a `Crystal::Call` with name `+` (string concat) producing the same.
  # Parameterised calls (`db.query("... WHERE id = ?", id)`) don't fire
  # because their first arg is a `StringLiteral`.
  class SqlStringBuild < AstRule
    def id : String
      "FLAW003"
    end

    def title : String
      "SQL built by string interpolation or concatenation"
    end

    def default_severity : Severity
      Severity::High
    end

    def description : String
      <<-DESC
      A SQL statement was assembled using interpolation or `+` concatenation
      before being passed to a DB client. Use parameterised queries
      (`db.query("... WHERE id = ?", id)`) instead.
      DESC
    end

    DB_CALLS    = {"query", "exec", "scalar", "query_one", "query_all", "query_one?"}
    SQL_KEYWORD = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE|FROM|INTO)\b/i

    def visit(node, source : String, path : String, findings : Array(Finding)) : Nil
      return unless node.is_a?(Crystal::Call)
      return unless DB_CALLS.includes?(node.name)
      first = node.args.first?
      return unless first
      case first
      when Crystal::StringInterpolation
        return unless interpolation_has_sql?(first)
        report(first, source, path, findings,
          "SQL built via interpolation — use parameterised queries")
      when Crystal::Call
        return unless first.name == "+" && concat_has_sql?(first)
        report(first, source, path, findings,
          "SQL built via string concatenation — use parameterised queries")
      end
    end

    private def interpolation_has_sql?(node : Crystal::StringInterpolation) : Bool
      node.expressions.any? do |e|
        e.is_a?(Crystal::StringLiteral) && e.value =~ SQL_KEYWORD
      end
    end

    private def concat_has_sql?(node : Crystal::Call) : Bool
      node.to_s =~ SQL_KEYWORD ? true : false
    end

    private def report(node, source, path, findings, msg) : Nil
      line = node.location.try(&.line_number) || 1
      col  = node.location.try(&.column_number) || 0
      findings << finding(source, path, line, col - 1, msg)
    end
  end
end
