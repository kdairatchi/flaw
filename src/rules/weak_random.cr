require "./rule"
require "./context"

module Flaw
  class WeakRandom < Rule
    def id : String
      "FLAW004"
    end

    def title : String
      "Non-cryptographic RNG used for security-sensitive value"
    end

    def default_severity : Severity
      Severity::High
    end

    def description : String
      <<-DESC
      A call to `rand`, `Random::DEFAULT`, or `Random.new` appears near a
      security-sensitive identifier (token, password, session, nonce, otp,
      reset, secret, api_key). Use `Random::Secure` for unpredictability.
      DESC
    end

    SENSITIVE = /\b(token|password|passwd|pwd|session|nonce|otp|reset|secret|api[_-]?key|csrf)\b/i
    WEAK_CALL = /\b(rand(?:om)?(?:\.|::)|Random::DEFAULT|Random\.new)/

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless RuleContext.code_path?(path)
      return [] of Finding if RuleContext.test_path?(path) || RuleContext.doc_path?(path)

      results = [] of Finding
      lines = source.split('\n')
      lines.each_with_index do |line, i|
        next if RuleContext.comment_only?(line)
        next unless m = line.match(WEAK_CALL)
        next if line.includes?("Random::Secure")

        window_start = [i - 2, 0].max
        window_end = [i + 2, lines.size - 1].min

        # Find a sensitive match inside the window and make sure the line it
        # came from isn't itself just a comment (e.g. "# TODO rotate token").
        hit = false
        (window_start..window_end).each do |j|
          wline = lines[j]
          next if RuleContext.comment_only?(wline)
          if wline =~ SENSITIVE
            hit = true
            break
          end
        end
        next unless hit

        results << finding(source, path, i + 1, m.begin(0) || 0,
          "Weak RNG near security-sensitive identifier — use Random::Secure")
      end
      results
    end
  end
end
