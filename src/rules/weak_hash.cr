require "./rule"

module Flaw
  class WeakHash < Rule
    def id : String
      "FLAW009"
    end

    def title : String
      "Weak hash used for password or integrity"
    end

    def default_severity : Severity
      Severity::High
    end

    def description : String
      <<-DESC
      MD5 or SHA1 were used near a security-sensitive identifier (password,
      token, hmac, signature, digest, integrity). Both are broken for
      collision resistance and unfit for password hashing at any cost factor.
      Use `Crypto::Bcrypt`, Argon2, or SHA-256+ for integrity.
      DESC
    end

    WEAK_CALL  = /\b(Digest::MD5|Digest::SHA1|OpenSSL::Digest\.new\("(?:MD5|SHA1)"\))/
    SENSITIVE  = /\b(password|passwd|pwd|hmac|signature|digest|integrity|hash_password|verify)\b/i

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      lines = source.split('\n')
      lines.each_with_index do |line, i|
        next if line.lstrip.starts_with?('#')
        next unless m = line.match(WEAK_CALL)
        window_start = [i - 2, 0].max
        window_end = [i + 2, lines.size - 1].min
        window = lines[window_start..window_end].join('\n')
        next unless window =~ SENSITIVE
        results << finding(source, path, i + 1, m.begin(0) || 0,
          "Weak hash (#{m[0]}) used near security-sensitive name — use Crypto::Bcrypt for passwords, SHA-256 for integrity")
      end
      results
    end
  end
end
