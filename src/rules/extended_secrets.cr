require "./rule"
require "./context"

module Flaw
  # FLAW137 — Modern provider token formats (extends FLAW002).
  class ExtendedSecrets < Rule
    def id : String
      "FLAW137"
    end

    def title : String
      "Possible provider token"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      Detects modern provider credentials (OpenAI, Anthropic, HuggingFace,
      npm, PyPI, Vault, Telegram, Discord, Twilio, SendGrid, Mailgun) in
      source. Rotate any match immediately and move to a secret manager.
      DESC
    end

    # Order matters — Anthropic before OpenAI so sk-ant- wins.
    PATTERNS = [
      {name: "Anthropic", rx: /\bsk-ant-(?:api|admin)\d+-[A-Za-z0-9\-_]{80,}\b/},
      {name: "OpenAI", rx: /\bsk-(?!ant-)[A-Za-z0-9]{20,}\b/},
      {name: "HuggingFace", rx: /\bhf_[A-Za-z0-9]{34,}\b/},
      {name: "npm", rx: /\bnpm_[A-Za-z0-9]{36,}\b/},
      {name: "PyPI", rx: /\bpypi-AgEI[A-Za-z0-9_\-]{50,}\b/},
      {name: "Vault", rx: /\bhvs\.[A-Za-z0-9_\-]{24,}\b/},
      {name: "Telegram bot", rx: /\b\d{8,10}:[A-Za-z0-9_\-]{35}\b/},
      {name: "Discord webhook", rx: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_\-]{60,}/},
      {name: "Twilio SID", rx: /\bAC[a-f0-9]{32}\b/},
      {name: "Twilio API SID", rx: /\bSK[a-f0-9]{32}\b/},
      {name: "SendGrid", rx: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/},
      {name: "Mailgun", rx: /\bkey-[a-f0-9]{32}\b/},
    ]

    VAULT_LEGACY = /\bs\.[A-Za-z0-9]{24}\b/

    SELF_RX = /\\b|PATTERNS|FIXTURES/

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding if RuleContext.lock_path?(path) ||
                              RuleContext.test_path?(path) ||
                              RuleContext.doc_path?(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line =~ SELF_RX
        PATTERNS.each do |entry|
          if m = line.match(entry[:rx])
            results << finding(source, path, idx, m.begin(0) || 0,
              "Possible #{entry[:name]} token in source — rotate and move to secret manager")
            break
          end
        end
        # Vault legacy: require 'vault' on the line to curb false positives.
        if line.downcase.includes?("vault")
          if m = line.match(VAULT_LEGACY)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Possible Vault token in source — rotate and move to secret manager")
          end
        end
      end
      results
    end
  end
end
