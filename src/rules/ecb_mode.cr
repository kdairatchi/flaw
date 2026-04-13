require "./rule"

module Flaw
  # FLAW020 — ECB mode. Deterministic, leaks plaintext structure.
  class EcbMode < Rule
    def id : String
      "FLAW020"
    end

    def title : String
      "ECB cipher mode used"
    end

    def default_severity : Severity
      Severity::High
    end

    def description : String
      <<-DESC
      ECB encrypts identical plaintext blocks to identical ciphertext blocks,
      leaking structure (the "ECB penguin"). Use an AEAD mode — AES-GCM or
      ChaCha20-Poly1305.
      DESC
    end

    PATTERN = /["']aes[-_]?\d+[-_]ecb["']|OpenSSL::Cipher.*ECB/i

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        if m = line.match(PATTERN)
          results << finding(source, path, idx, m.begin(0) || 0,
            "ECB mode — switch to AES-GCM or ChaCha20-Poly1305 for authenticated encryption")
        end
      end
      results
    end
  end
end
