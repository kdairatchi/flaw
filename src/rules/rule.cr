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

    # CWE / OWASP metadata mirrored from each rule's `rules/FLAWNNN/rule.yml`.
    # Kept centrally so SARIF output can emit taxa without every Rule class
    # having to reopen itself.
    METADATA = {
      "FLAW001" => {cwe: "CWE-78",   owasp: "A03:2021"},
      "FLAW002" => {cwe: "CWE-798",  owasp: "A07:2021"},
      "FLAW003" => {cwe: "CWE-89",   owasp: "A03:2021"},
      "FLAW004" => {cwe: "CWE-338",  owasp: "A02:2021"},
      "FLAW005" => {cwe: "CWE-502",  owasp: "A08:2021"},
      "FLAW006" => {cwe: "CWE-22",   owasp: "A01:2021"},
      "FLAW007" => {cwe: "CWE-601",  owasp: "A01:2021"},
      "FLAW008" => {cwe: "CWE-502",  owasp: "A08:2021"},
      "FLAW009" => {cwe: "CWE-328",  owasp: "A02:2021"},
      "FLAW010" => {cwe: "CWE-295",  owasp: "A02:2021"},
      "FLAW011" => {cwe: "CWE-918",  owasp: "A10:2021"},
      "FLAW012" => {cwe: "CWE-208",  owasp: "A02:2021"},
      "FLAW013" => {cwe: "CWE-377",  owasp: "A01:2021"},
      "FLAW014" => {cwe: "CWE-611",  owasp: "A05:2021"},
      "FLAW015" => {cwe: "CWE-915",  owasp: "A01:2021"},
      "FLAW016" => {cwe: "CWE-326",  owasp: "A02:2021"},
      "FLAW017" => {cwe: "CWE-1333", owasp: "A05:2021"},
      "FLAW018" => {cwe: "CWE-532",  owasp: "A09:2021"},
      "FLAW019" => {cwe: "CWE-1004", owasp: "A05:2021"},
      "FLAW020" => {cwe: "CWE-327",  owasp: "A02:2021"},
      "FLAW021" => {cwe: "CWE-329",  owasp: "A02:2021"},
      "FLAW022" => {cwe: "CWE-22",   owasp: "A01:2021"},
      "FLAW023" => {cwe: "CWE-347",  owasp: "A02:2021"},
      "FLAW024" => {cwe: "CWE-942",  owasp: "A05:2021"},
      "FLAW103" => {cwe: "CWE-1163", owasp: nil},
      "FLAW104" => {cwe: "CWE-390",  owasp: nil},
      "FLAW105" => {cwe: "CWE-862",  owasp: "A01:2021"},
    }

    def cwe : String?
      METADATA[id]?.try(&.[:cwe])
    end

    def owasp : String?
      METADATA[id]?.try(&.[:owasp])
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
