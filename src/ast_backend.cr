{% begin %}
  {% if flag?(:flaw_no_ast) %}
    # AST backend disabled at build time.
  {% else %}
    require "compiler/crystal/syntax"
  {% end %}
{% end %}

module Flaw
  # AST-backed analysis tier. Parses a source file with `Crystal::Parser`
  # (same path Ameba uses) and dispatches `AstRule` instances through a
  # shared visitor. Regex rules remain the default substrate — AST rules
  # opt in by subclassing `AstRule` instead of `Rule`. Files that fail to
  # parse are skipped by this tier and still get regex coverage.
  module AstBackend
    def self.available? : Bool
      {% if flag?(:flaw_no_ast) %}
        false
      {% else %}
        true
      {% end %}
    end

    # Parses source. Returns nil on any parse error so callers can fall
    # back to regex-only without aborting the whole scan.
    def self.parse(source : String) : Crystal::ASTNode?
      {% if flag?(:flaw_no_ast) %}
        nil
      {% else %}
        begin
          Crystal::Parser.new(source).parse
        rescue
          nil
        end
      {% end %}
    end

    def self.run(rules : Array(AstRule), source : String, path : String) : Array(Finding)
      findings = [] of Finding
      return findings if rules.empty?
      root = parse(source)
      return findings unless root
      {% unless flag?(:flaw_no_ast) %}
        Taint.current_bindings = Analysis.collect(root)
      {% end %}
      begin
        visitor = Visitor.new(rules, source, path, findings)
        root.accept(visitor)
      ensure
        Taint.current_bindings = nil
      end
      findings
    end

    {% if flag?(:flaw_no_ast) %}
      # Stub visitor so the rest of the module compiles when AST is off.
      class Visitor
        def initialize(@rules : Array(AstRule), @source : String, @path : String, @findings : Array(Finding))
        end

        def visit(node) : Bool
          true
        end
      end
    {% else %}
      class Visitor < Crystal::Visitor
        def initialize(@rules : Array(AstRule), @source : String, @path : String, @findings : Array(Finding))
        end

        def visit(node : Crystal::ASTNode) : Bool
          @rules.each do |rule|
            rule.visit(node, @source, @path, @findings)
          end
          true
        end
      end
    {% end %}
  end
end
