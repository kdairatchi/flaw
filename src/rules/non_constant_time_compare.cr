require "./rule"

module Flaw
  # FLAW012 — Timing attack. Equality comparison between a user-supplied
  # value and a secret (token/password/hmac/signature) using `==`. Use
  # `Crypto::Subtle.constant_time_compare` instead.
  class NonConstantTimeCompare < Rule
    def id : String
      "FLAW012"
    end

    def title : String
      "Secret compared with == (timing attack)"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def description : String
      <<-DESC
      A secret-named value was compared with `==`, which short-circuits on the
      first differing byte and leaks length/prefix through timing. Use
      `Crypto::Subtle.constant_time_compare(a, b)` for tokens, HMACs, and
      signature checks.
      DESC
    end

    SENSITIVE = /\b(token|hmac|signature|api[_-]?key|secret|auth(?:_?header)?|csrf|mac|digest_expected|expected_(?:hmac|sig|token))\b/i
    COMPARE   = /\b(\w+)\s*==\s*(\w+)/

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        next unless line =~ SENSITIVE
        if m = line.match(COMPARE)
          left, right = m[1], m[2]
          next unless (left =~ SENSITIVE) || (right =~ SENSITIVE)
          next if line.includes?("constant_time_compare")
          results << finding(source, path, idx, m.begin(0) || 0,
            "Use Crypto::Subtle.constant_time_compare for secret equality — `==` leaks via timing")
        end
      end
      results
    end
  end
end
