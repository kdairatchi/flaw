require "./rule"
require "./context"

module Flaw
  # FLAW116 — unsafe deserialization (pickle/Marshal/unsafe YAML/Oj).
  class UnsafeDeserializePickle < Rule
    def id : String
      "FLAW116"
    end

    def title : String
      "Unsafe deserialization sink"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      pickle, cPickle, dill, shelve, Ruby Marshal, YAML.unsafe_load and Oj
      without a safe mode will execute arbitrary code embedded in the byte
      stream. Use JSON, MessagePack, or explicitly safe loaders.
      DESC
    end

    PY_PATTERNS = [
      /\bpickle\.loads?\s*\(/,
      /\bcPickle\.loads?\s*\(/,
      /\b_pickle\.loads?\s*\(/,
      /\bshelve\.open\s*\(/,
      /\bdill\.loads?\s*\(/,
    ]

    RB_PATTERNS = [
      /\bMarshal\.load\s*\(/,
      /\bOj\.load\s*\([^)]*\)/,
      /\bYAML\.unsafe_load\s*\(/,
    ]

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding if RuleContext.test_path?(path) || RuleContext.doc_path?(path)
      patterns = if path.ends_with?(".py")
                   PY_PATTERNS
                 elsif path.ends_with?(".rb")
                   RB_PATTERNS
                 else
                   return [] of Finding
                 end
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        patterns.each do |rx|
          if m = line.match(rx)
            # Oj.load with mode: is safe — skip.
            if rx.source.includes?("Oj") && line.includes?("mode:")
              break
            end
            results << finding(source, path, idx, m.begin(0) || 0,
              "Unsafe deserialization — byte-stream can execute arbitrary code")
            break
          end
        end
      end
      results
    end
  end
end
