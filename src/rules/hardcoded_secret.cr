require "./rule"

module Flaw
  class HardcodedSecret < Rule
    def id : String
      "FLAW002"
    end

    def title : String
      "Hardcoded secret literal"
    end

    def default_severity : Severity
      Severity::High
    end

    def description : String
      <<-DESC
      A string literal matched a known secret format (AWS key, GitHub token,
      Slack token, private key header, or a generic high-entropy API key
      assigned to a secret-named variable).
      DESC
    end

    PATTERNS = {
      "AWS access key"    => /\bAKIA[0-9A-Z]{16}\b/,
      "GitHub token"      => /\bghp_[A-Za-z0-9]{36,}\b/,
      "GitHub fine-grained token" => /\bgithub_pat_[A-Za-z0-9_]{22,}\b/,
      "Slack token"       => /\bxox[abpsr]-[A-Za-z0-9-]{10,}\b/,
      "Google API key"    => /\bAIza[0-9A-Za-z\-_]{35}\b/,
      "Private key"       => /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
      "Stripe live key"   => /\bsk_live_[0-9a-zA-Z]{24,}\b/,
    }

    NAMED_ASSIGN = /\b(api[_-]?key|secret|token|password|passwd|pwd|auth)\s*=\s*"([^"]{16,})"/i

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        PATTERNS.each do |label, re|
          if m = line.match(re)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Possible #{label} committed to source")
          end
        end
        if m = line.match(NAMED_ASSIGN)
          value = m[2]
          # skip obvious placeholders
          next if value =~ /^(your[_-]?|example|placeholder|xxx+|changeme|todo)/i
          next if value.chars.uniq.size < 6
          next if Entropy.shannon(value) < 3.5
          results << finding(source, path, idx, m.begin(0) || 0,
            "Hardcoded secret assigned to '#{m[1]}' — move to ENV or config file")
        end
      end
      results
    end
  end
end
