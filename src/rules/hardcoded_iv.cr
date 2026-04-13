require "./rule"

module Flaw
  # FLAW021 — Hardcoded IV / nonce / salt. Destroys confidentiality in CTR
  # and AEAD modes; breaks key-derivation uniqueness.
  class HardcodedIv < Rule
    def id : String
      "FLAW021"
    end

    def title : String
      "Hardcoded IV / nonce / salt"
    end

    def default_severity : Severity
      Severity::High
    end

    def description : String
      <<-DESC
      An IV, nonce, or salt was assigned a literal byte string. Reusing an
      IV with a stream/AEAD mode leaks plaintext XOR pairs and, with GCM,
      allows full authentication key recovery. Generate a fresh random IV
      per message with `Random::Secure.random_bytes(12)` and prepend it to
      the ciphertext.
      DESC
    end

    # iv = "abcdef..." / nonce = Bytes[0, 1, 2, ...] / salt = "..."
    NAMED = /\b(iv|nonce|salt)\s*=\s*(?:"([^"]{8,})"|Bytes\[[^\]]+\]|Slice\[[^\]]+\])/i

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        if m = line.match(NAMED)
          next if line.includes?("Random::Secure") || line.includes?("SecureRandom")
          results << finding(source, path, idx, m.begin(0) || 0,
            "Hardcoded #{m[1]} — generate per-message via Random::Secure.random_bytes")
        end
      end
      results
    end
  end
end
