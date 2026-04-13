require "./analysis/bindings"

module Flaw
  # Shape-based taint predicates. This is deliberately *local* — we look at
  # direct AST node shapes without full call-graph tracing. It's enough to
  # kill the common false positives (string coercion, parameterised calls,
  # constant strings) without shipping a taint engine.
  module Taint
    # Known web-input sources. If an interpolated expression reads from one
    # of these, we treat it as tainted.
    TAINTED_RECEIVERS = {"params", "request", "session", "cookies", "headers", "ARGV", "ENV"}
    TAINTED_CALLS     = {"query_params", "path_params", "form_params", "body", "read_string"}
    TAINTED_PARAM_RE  = /\A(user_|raw_|unsafe_|untrusted_|input|body|payload|params|query|q|url|uri|path|name|id|cmd|command)\b/i

    # Known sanitizers. A call wrapping a tainted value in one of these
    # neutralises taint for our purposes.
    SANITIZER_CALLS = {
      "to_i", "to_i32", "to_i64", "to_u32", "to_u64", "to_f", "to_f32", "to_f64",
      "to_i?", "to_i64?", "to_f?",
      "encode_path", "encode_www_form", "escape",
      "constant_time_compare",
    }

    # Method receivers whose calls are generally safe (escape/encode classes).
    SAFE_RECEIVERS = {"URI", "HTML", "JSON", "Base64", "Crypto::Subtle"}

    # Per-file bindings, set by AstBackend.run for the duration of rule
    # dispatch. Rules resolve `Var` references through this to peek at the
    # RHS of local assignments.
    class_property current_bindings : Analysis::Bindings?

    def self.tainted?(node) : Bool
      return false unless node.is_a?(Crystal::ASTNode)
      case node
      when Crystal::Call
        # x.to_i on a tainted thing is no longer tainted
        return false if sanitized_call?(node)
        # params["x"], ENV["HOME"], request.body
        if obj = node.obj
          return true if TAINTED_CALLS.includes?(node.name)
          return true if obj.is_a?(Crystal::Var | Crystal::Call) && tainted_source?(obj)
          return tainted?(obj)
        end
        false
      when Crystal::Var
        tainted_source?(node)
      when Crystal::Path
        false
      when Crystal::StringInterpolation
        node.expressions.any? { |e| tainted?(e) }
      else
        false
      end
    end

    def self.sanitized_call?(node : Crystal::Call) : Bool
      return true if SANITIZER_CALLS.includes?(node.name)
      if obj = node.obj
        return true if SAFE_RECEIVERS.includes?(obj.to_s) && {"escape", "encode", "encode_path", "encode_www_form"}.any? { |n| node.name.starts_with?(n) }
      end
      false
    end

    def self.tainted_source?(node) : Bool
      case node
      when Crystal::Var
        !!(node.name.to_s =~ TAINTED_PARAM_RE)
      when Crystal::Call
        name = node.obj.try(&.to_s) || ""
        return true if TAINTED_RECEIVERS.includes?(name)
        return true if TAINTED_CALLS.includes?(node.name)
        false
      else
        false
      end
    end
  end
end
