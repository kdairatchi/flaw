require "./rule"
require "./context"

module Flaw
  # FLAW107 — hardcoded external URL or IP in production source.
  # Production URLs and IPs belong in config/ENV, not in code — otherwise
  # staging/prod can't diverge and rotation is impossible.
  class HardcodedUrl < Rule
    def id : String
      "FLAW107"
    end

    def title : String
      "Hardcoded external URL or IP in source"
    end

    def default_severity : Severity
      Severity::Low
    end

    def tag : String
      "hygiene"
    end

    def description : String
      <<-DESC
      An http(s):// URL pointing at a non-local host, or a public IP literal,
      is embedded in source code. Move it to configuration (ENV var,
      settings file) so environments can diverge and endpoints can rotate
      without a code change.
      DESC
    end

    URL_RX = %r{https?://([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,})(:\d+)?(/[^\s"'`<>)\]]*)?}
    IP_RX  = /\b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\b/

    LOCAL_HOSTS = %w(localhost example.com example.org example.net schemas.xmlsoap.org www.w3.org xmlns.jcp.org
      www.example.com httpbin.org invalid test.local)
    LOCAL_IP_RX = /\A(?:10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.0\.0\.0\z|255\.255\.255\.255\z)/

    # Hosts that appear as schema constants, license references, or framework
    # documentation anchors — never real endpoints to route traffic through.
    WELLKNOWN_HOSTS = %w(
      raw.githubusercontent.com schemas.xmlsoap.org www.w3.org xmlns.jcp.org
      schema.org spdx.org opensource.org creativecommons.org tools.ietf.org
      datatracker.ietf.org docs.oasis-open.org cwe.mitre.org cve.mitre.org
      owasp.org nvd.nist.gov)
    # Scaffolding / template / fixture output paths where URLs are template
    # material, not endpoints.
    SCAFFOLD_PATH_RX = %r{/(scaffold|scaffolds|templates?|examples?|samples?|generators?|init|skeleton)s?/}i

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless RuleContext.code_path?(path) || RuleContext.web_path?(path)
      return [] of Finding if RuleContext.test_path?(path)
      return [] of Finding if RuleContext.lock_path?(path)
      return [] of Finding if SCAFFOLD_PATH_RX.match(path)
      # Branding files (project home-page URLs) shouldn't be flagged — these
      # are display strings, not API endpoints.
      return [] of Finding if path =~ %r{/branding\.|/version\.|/about\.}i
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        # skip obvious ENV-fallback patterns: ENV["API"] || "https://..."
        next if line =~ /ENV\s*\[|process\.env\.|os\.getenv/
        # skip JSON-Schema / $schema / informationUri style metadata keys.
        next if line =~ /(["'])\$?schema(["']|:)|informationUri|spdx|licenseUrl/i
        if m = line.match(URL_RX)
          host = m[1].downcase
          next if WELLKNOWN_HOSTS.includes?(host)
          unless LOCAL_HOSTS.any? { |h| host == h || host.ends_with?(".#{h}") }
            results << finding(source, path, idx, m.begin(0) || 0,
              "Hardcoded URL to '#{host}' — move endpoint to config/ENV")
            next
          end
        end
        if m = line.match(IP_RX)
          ip = m[1]
          next if LOCAL_IP_RX.match(ip)
          results << finding(source, path, idx, m.begin(0) || 0,
            "Hardcoded public IP '#{ip}' — move to config/ENV")
        end
      end
      results
    end
  end
end
