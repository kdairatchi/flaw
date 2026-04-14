require "./rule"
require "./context"

module Flaw
  # FLAW142 — deobfuscate-then-invoke chains (T1027 / T1059).
  class ObfuscatedInvoke < Rule
    def id : String
      "FLAW142"
    end

    def title : String
      "Obfuscated code execution chain"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      Chains like `IEX([Convert]::FromBase64String(...))` or
      `[Reflection.Assembly]::Load(...)` are the canonical PowerShell dropper
      pattern. Source shipping these is either red-team tooling or a backdoor.
      DESC
    end

    PATTERNS = [
      /FromBase64String\s*\([^)]+\)[^\n]*(?:IEX|Invoke-Expression)/i,
      /(?:IEX|Invoke-Expression)\s*\(\s*(?:\[System\.Text\.Encoding\]::\w+\.GetString|\[Convert\]::FromBase64String|[-]join|Compress)/i,
      /\[System\.Reflection\.Assembly\]::Load\s*\(/i,
      /\[Reflection\.Assembly\]::Load\s*\(/i,
    ]

    # UTF-16 base64 prefixes that decode to "IE"/"IEX" etc.
    IEX_PREFIX_RX = /["'`](SQBF|SUBF|SQBl|SQBG|SUBG)[A-Za-z0-9+\/=]{36,}["'`]/

    EXTS = %w(.ps1 .psm1 .psd1 .bat .cmd .yml .yaml .js)

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding if RuleContext.test_path?(path) || RuleContext.doc_path?(path)
      base = path.split('/').last
      ok = EXTS.any? { |e| path.ends_with?(e) } || base == "Dockerfile" || base.starts_with?("Dockerfile")
      return [] of Finding unless ok
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        hit = false
        PATTERNS.each do |rx|
          if m = line.match(rx)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Obfuscated code execution chain — T1027 / T1059 deobfuscate-then-invoke")
            hit = true
            break
          end
        end
        next if hit
        if m = line.match(IEX_PREFIX_RX)
          results << finding(source, path, idx, m.begin(0) || 0,
            "Obfuscated code execution chain — T1027 / T1059 deobfuscate-then-invoke")
        end
      end
      results
    end
  end
end
