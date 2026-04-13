{% begin %}
  {% unless flag?(:flaw_no_ast) %}
    require "compiler/crystal/syntax"
  {% end %}
{% end %}

module Flaw::Analysis
  # Intraprocedural local-variable bindings. Flat per-file: if the same name
  # is reassigned, the last RHS wins. This is intentionally imprecise — it's
  # enough to let rules resolve `cmd = "literal"; system("echo #{cmd}")`
  # without shipping SSA or a flow graph.
  class Bindings
    getter locals : Hash(String, Crystal::ASTNode)

    def initialize
      @locals = {} of String => Crystal::ASTNode
    end

    def resolve(name : String) : Crystal::ASTNode?
      @locals[name]?
    end
  end

  {% unless flag?(:flaw_no_ast) %}
    class BindingCollector < Crystal::Visitor
      getter bindings : Bindings

      def initialize
        @bindings = Bindings.new
      end

      def visit(node : Crystal::Assign) : Bool
        if (target = node.target).is_a?(Crystal::Var)
          @bindings.locals[target.name] = node.value
        end
        true
      end

      def visit(node : Crystal::ASTNode) : Bool
        true
      end
    end

    def self.collect(root : Crystal::ASTNode) : Bindings
      c = BindingCollector.new
      root.accept(c)
      c.bindings
    end
  {% end %}
end
