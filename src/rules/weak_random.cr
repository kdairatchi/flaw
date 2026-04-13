require "./rule"

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
      results = [] of Finding
      lines = source.split('\n')
      lines.each_with_index do |line, i|
        next if line.lstrip.starts_with?('#')
        next unless m = line.match(WEAK_CALL)
        # look 2 lines up and down for sensitive identifier
        window_start = [i - 2, 0].max
        window_end = [i + 2, lines.size - 1].min
        window = lines[window_start..window_end].join('\n')
        next unless window =~ SENSITIVE
        # skip Random::Secure
        next if line.includes?("Random::Secure")
        results << finding(source, path, i + 1, m.begin(0) || 0,
          "Weak RNG near security-sensitive identifier — use Random::Secure")
      end
      results
    end
  end
end
