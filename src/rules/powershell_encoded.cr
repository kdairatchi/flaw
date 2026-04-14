require "./rule"
require "./context"

module Flaw
  # FLAW138 — PowerShell encoded/hidden payloads (LOLBAS evasion, T1059.001).
  class PowershellEncoded < Rule
    def id : String
      "FLAW138"
    end

    def title : String
      "PowerShell encoded/hidden command"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      PowerShell invoked with `-EncodedCommand` or `-WindowStyle Hidden -NoProfile`
      is the hallmark of living-off-the-land malware droppers. Source trees should
      never ship such lines; investigate anything that matches.
      DESC
    end

    PATTERNS = [
      /powershell(?:\.exe)?\s+[^\n]*-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\b/i,
      /pwsh(?:\.exe)?\s+[^\n]*-enc(?:odedcommand)?\b/i,
      /powershell(?:\.exe)?\s+[^\n]*-(?:nop|noprofile).*-(?:w|win|windowstyle)\s+hidden/i,
    ]

    EXTS = %w(.sh .bash .zsh .ps1 .psm1 .psd1 .bat .cmd .yml .yaml .ecr .erb .hbs)

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding if RuleContext.test_path?(path) || RuleContext.doc_path?(path) || RuleContext.lock_path?(path)
      base = path.split('/').last
      ok = EXTS.any? { |e| path.ends_with?(e) } || base == "Dockerfile" || base.starts_with?("Dockerfile")
      return [] of Finding unless ok
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        PATTERNS.each do |rx|
          if m = line.match(rx)
            results << finding(source, path, idx, m.begin(0) || 0,
              "PowerShell encoded/hidden command — common living-off-the-land evasion (T1059.001)")
            break
          end
        end
      end
      results
    end
  end
end
