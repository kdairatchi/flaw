module Flaw
  abstract class Rule
    abstract def id : String
    abstract def title : String
    abstract def default_severity : Severity
    abstract def description : String
    abstract def check(source : String, path : String) : Array(Finding)

    # Category for grouping in `flaw rules` output and the README catalog.
    # Override in rule subclasses. Default: "security".
    def tag : String
      "security"
    end

    REGISTRY = [] of Rule.class

    macro inherited
      {% unless @type.abstract? %}
        Flaw::Rule::REGISTRY << {{@type}}
      {% end %}
    end

    def self.all : Array(Rule)
      REGISTRY.map(&.new.as(Rule))
    end

    protected def snippet_of(source : String, line : Int32) : String
      lines = source.split('\n')
      return "" if line < 1 || line > lines.size
      lines[line - 1].strip[0, 200]
    end

    protected def finding(source, path, line, column, message) : Finding
      Finding.new(id, default_severity, title, message, path, line, column, snippet_of(source, line))
    end
  end

  # AST-backed rule. Subclasses override `visit` and are fed every parsed
  # node by a shared `AstBackend::Visitor`, so each file is parsed once
  # regardless of how many AST rules are active. `check` is a no-op — the
  # Scanner routes these through the AST tier instead.
  abstract class AstRule < Rule
    def check(source : String, path : String) : Array(Finding)
      [] of Finding
    end

    abstract def visit(node, source : String, path : String, findings : Array(Finding)) : Nil
  end
end
