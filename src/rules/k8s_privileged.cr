require "./rule"
require "./context"

module Flaw
  # FLAW146 — Kubernetes manifest with a pod/container security boundary
  # explicitly disabled (privileged, hostNetwork, runAsUser 0, etc.).
  class K8sPrivileged < Rule
    def id : String
      "FLAW146"
    end

    def title : String
      "Kubernetes security boundary disabled"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      Container escapes and host takeover frequently start from a manifest
      that waives a default security boundary — `privileged: true`,
      `hostNetwork`, `hostPID`, running as UID 0, disabling
      `readOnlyRootFilesystem`, or adding dangerous capabilities like
      SYS_ADMIN/NET_ADMIN/ALL. Keep the defaults and drop capabilities
      explicitly.
      DESC
    end

    PATTERNS = [
      {rx: /^\s*privileged\s*:\s*true\b/, field: "privileged", value: "true"},
      {rx: /^\s*hostNetwork\s*:\s*true\b/, field: "hostNetwork", value: "true"},
      {rx: /^\s*hostPID\s*:\s*true\b/, field: "hostPID", value: "true"},
      {rx: /^\s*hostIPC\s*:\s*true\b/, field: "hostIPC", value: "true"},
      {rx: /^\s*runAsUser\s*:\s*0\b/, field: "runAsUser", value: "0"},
      {rx: /^\s*allowPrivilegeEscalation\s*:\s*true\b/, field: "allowPrivilegeEscalation", value: "true"},
      {rx: /^\s*readOnlyRootFilesystem\s*:\s*false\b/, field: "readOnlyRootFilesystem", value: "false"},
      {rx: /^\s*-\s*(SYS_ADMIN|NET_ADMIN|ALL)\s*$/, field: "capabilities.add", value: "dangerous"},
      {rx: /add\s*:\s*\[[^\]]*(?:SYS_ADMIN|NET_ADMIN|ALL)[^\]]*\]/, field: "capabilities.add", value: "dangerous"},
    ]

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless path.ends_with?(".yml") || path.ends_with?(".yaml")
      return [] of Finding if RuleContext.test_path?(path) || RuleContext.doc_path?(path)

      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        PATTERNS.each do |pat|
          if m = line.match(pat[:rx])
            results << finding(source, path, idx, m.begin(0) || 0,
              "Kubernetes security boundary disabled (#{pat[:field]}: #{pat[:value]}) — privilege escalation risk")
            break
          end
        end
      end
      results
    end
  end
end
