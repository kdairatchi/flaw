require "./rule"
require "./context"

module Flaw
  # FLAW139 — remote script piped to shell (no integrity, MITM-able).
  class CurlPipeShell < Rule
    def id : String
      "FLAW139"
    end

    def title : String
      "Remote script piped to shell"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      `curl URL | bash` (and variants) executes whatever the server returns with
      no hash pinning and no TLS failure stop. A one-time MITM or a compromised
      CDN becomes RCE. Download, verify a known SHA-256, then execute.
      DESC
    end

    PATTERNS = [
      /\bcurl\b[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/,
      /\bwget\b[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/,
      /\bfetch\b[^|]*\|\s*(?:ba)?sh\b/,
      /\b(?:curl|wget)\s[^\n]*\|\s*python\d?\b/,
      /\b(?:curl|wget)\s[^\n]*\|\s*perl\b/,
    ]

    EXTS = %w(.sh .bash .zsh .fish .yml .yaml .ps1)

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding if RuleContext.test_path?(path) || RuleContext.doc_path?(path)
      base = path.split('/').last
      ok = EXTS.any? { |e| path.ends_with?(e) } ||
           base == "Dockerfile" || base.starts_with?("Dockerfile") ||
           base == "Makefile" || base == "GNUmakefile"
      return [] of Finding unless ok
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        PATTERNS.each do |rx|
          if m = line.match(rx)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Remote script piped to shell — MITM + no integrity check; pin SHA and verify")
            break
          end
        end
      end
      results
    end
  end
end
