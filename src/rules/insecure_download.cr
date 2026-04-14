require "./rule"
require "./context"

module Flaw
  # FLAW114 — package or script fetched over insecure http://.
  class InsecureDownload < Rule
    def id : String
      "FLAW114"
    end

    def title : String
      "Insecure http:// download"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      Fetching installers, archives, or scripts over plain http:// exposes
      the supply chain to MITM tampering. Always use https:// and, where
      possible, verify checksums or signatures.
      DESC
    end

    CURL_WGET_RX = /\b(?:curl|wget)\b[^#\n]*\bhttp:\/\//
    PY_URLOPEN   = /urlopen\(\s*["']http:\/\//
    PY_REQUESTS  = /requests\.\w+\(\s*["']http:\/\//
    DOCKER_ADD   = /^\s*ADD\s+http:\/\//i
    DOCKER_RUN   = /^\s*RUN\b[^#\n]*\bhttp:\/\//i
    SH_ARCHIVE   = /http:\/\/\S+\.(?:tar\.gz|tgz|zip|deb|rpm|sh)\b/

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding if RuleContext.test_path?(path)
      base = path.split('/').last
      is_docker = base.starts_with?("Dockerfile")
      is_shell = path.ends_with?(".sh") || path.ends_with?(".bash")
      is_code = RuleContext.code_path?(path)
      return [] of Finding unless is_docker || is_shell || is_code
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        matched = nil
        if m = line.match(CURL_WGET_RX)
          matched = m
        elsif is_code && (m = line.match(PY_URLOPEN) || line.match(PY_REQUESTS))
          matched = m
        elsif is_docker && (m = line.match(DOCKER_ADD) || line.match(DOCKER_RUN))
          matched = m
        elsif (is_shell || is_docker) && (m = line.match(SH_ARCHIVE))
          matched = m
        end
        if matched
          results << finding(source, path, idx, matched.begin(0) || 0,
            "Package or script fetched over insecure http:// — MITM supply-chain risk")
        end
      end
      results
    end
  end
end
