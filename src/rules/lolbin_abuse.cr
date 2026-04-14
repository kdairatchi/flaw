require "./rule"
require "./context"

module Flaw
  # FLAW140 — Windows LOLBIN abuse signatures (T1218 proxy execution).
  class LolbinAbuse < Rule
    def id : String
      "FLAW140"
    end

    def title : String
      "LOLBIN abuse signature"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      Windows ships signed binaries (regsvr32, mshta, certutil, bitsadmin,
      rundll32, wmic, installutil, cscript) that attackers chain to bypass
      AV/EDR. Source code should never invoke them with the exploit flags.
      DESC
    end

    PATTERNS = [
      {rx: /regsvr32(?:\.exe)?\s+[^\n]*\/i:http/i, bin: "regsvr32"},
      {rx: /regsvr32(?:\.exe)?\s+[^\n]*scrobj\.dll/i, bin: "regsvr32"},
      {rx: /mshta(?:\.exe)?\s+[^\n]*(?:javascript|vbscript):/i, bin: "mshta"},
      {rx: /mshta(?:\.exe)?\s+https?:\/\//i, bin: "mshta"},
      {rx: /certutil(?:\.exe)?\s+[^\n]*-urlcache\s+-split\s+-f/i, bin: "certutil"},
      {rx: /certutil(?:\.exe)?\s+[^\n]*-decode\b/i, bin: "certutil"},
      {rx: /bitsadmin(?:\.exe)?\s+[^\n]*\/transfer\b/i, bin: "bitsadmin"},
      {rx: /rundll32(?:\.exe)?\s+[^\n]*javascript:/i, bin: "rundll32"},
      {rx: /wmic\s+process\s+call\s+create\b/i, bin: "wmic"},
      {rx: /installutil(?:\.exe)?\s+[^\n]*\/logfile=[^\s]+\s+\/LogToConsole=false/i, bin: "installutil"},
      {rx: /cscript(?:\.exe)?\s+[^\n]*\/\/e:jscript\b/i, bin: "cscript"},
    ]

    EXTS = %w(.sh .bat .cmd .ps1 .psm1 .yml .yaml .vbs .js .ts .py)

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding if RuleContext.test_path?(path) || RuleContext.doc_path?(path)
      base = path.split('/').last
      ok = EXTS.any? { |e| path.ends_with?(e) } || base == "Dockerfile" || base.starts_with?("Dockerfile")
      return [] of Finding unless ok
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        PATTERNS.each do |p|
          if m = line.match(p[:rx])
            results << finding(source, path, idx, m.begin(0) || 0,
              "LOLBIN abuse signature — #{p[:bin]} with exploit flags, common in T1218 proxy execution")
            break
          end
        end
      end
      results
    end
  end
end
