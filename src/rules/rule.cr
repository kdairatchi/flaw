module Flaw
  abstract class Rule
    abstract def id : String
    abstract def title : String
    abstract def default_severity : Severity
    abstract def description : String
    abstract def check(source : String, path : String) : Array(Finding)

    REGISTRY = [] of Rule.class

    macro inherited
      Flaw::Rule::REGISTRY << {{@type}}
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
end
