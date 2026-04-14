require "./rule"
require "./context"

module Flaw
  # FLAW123 — Prototype pollution sinks in JS/TS.
  class PrototypePollution < Rule
    def id : String
      "FLAW123"
    end

    def title : String
      "Prototype pollution sink"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      Deep-merging user-controlled objects into targets — or writing to
      __proto__/constructor.prototype — lets an attacker inject
      properties onto Object.prototype. Use Object.create(null), a
      Map, or a schema-validating merge.
      DESC
    end

    EXT = %w(.js .jsx .ts .tsx .mjs .cjs .vue .svelte)

    TAINT_RX  = /(?:req\.|request\.|params|userInput|body|query)/
    ASSIGN_RX = /Object\.assign\s*\(\s*[^,]+,\s*([^)]+)\)/
    MERGE_RX  = /(?:_|lodash)\.merge(?:With)?\s*\(([^)]*)\)/
    PROTO_RX  = /\[\s*["']__proto__["']\s*\]\s*=/
    CTOR_RX   = /\[\s*["']constructor["']\s*\]\s*\[\s*["']prototype["']\s*\]/
    JQ_EXT_RX = /\$\.extend\s*\(\s*true\s*,/

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless EXT.any? { |e| path.ends_with?(e) }
      return [] of Finding if RuleContext.test_path?(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        if m = line.match(ASSIGN_RX)
          if m[1] =~ TAINT_RX
            results << finding(source, path, idx, m.begin(0) || 0,
              "Prototype-pollution sink — deep merge of untrusted input")
            next
          end
        end
        if m = line.match(MERGE_RX)
          if m[1] =~ TAINT_RX
            results << finding(source, path, idx, m.begin(0) || 0,
              "Prototype-pollution sink — deep merge of untrusted input")
            next
          end
        end
        [PROTO_RX, CTOR_RX, JQ_EXT_RX].each do |rx|
          if m = line.match(rx)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Prototype-pollution sink — deep merge of untrusted input")
            break
          end
        end
      end
      results
    end
  end
end
