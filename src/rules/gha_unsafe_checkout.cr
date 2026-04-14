require "./rule"
require "./context"

module Flaw
  # FLAW144 — GitHub Actions pull_request_target workflow checking out the
  # attacker-controlled PR head. Classic supply-chain vector: the PR code runs
  # with a write-scoped GITHUB_TOKEN on the base repo.
  class GhaUnsafeCheckout < Rule
    def id : String
      "FLAW144"
    end

    def title : String
      "pull_request_target + PR-head checkout"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      A workflow triggered by `pull_request_target` runs in the context of the
      base repository and has access to secrets and a write-scoped
      GITHUB_TOKEN. Checking out the untrusted PR head (via
      `github.event.pull_request.head.sha` or `.ref`) causes attacker code to
      execute with those privileges. Use `pull_request` instead, or pin to the
      base SHA.
      DESC
    end

    WORKFLOW_PATH = %r{\.github/workflows/.*\.ya?ml$}
    PR_TARGET_RX  = /^\s*on\s*:.*pull_request_target/
    PR_TARGET_KEY = /^\s*pull_request_target\s*:/
    CHECKOUT_RX   = %r{uses\s*:\s*actions/checkout@}
    UNSAFE_REF_RX = /ref\s*:\s*\$?\{?\{?\s*github\.event\.pull_request\.head\.(sha|ref)/

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless path =~ WORKFLOW_PATH
      return [] of Finding if RuleContext.test_path?(path)

      lines = source.split('\n')
      has_pr_target = lines.any? { |l| l =~ PR_TARGET_RX || l =~ PR_TARGET_KEY }
      return [] of Finding unless has_pr_target

      results = [] of Finding
      checkout_line = 0
      lines.each_with_index do |line, i|
        if line =~ CHECKOUT_RX
          checkout_line = i + 1
        end
        if checkout_line > 0 && line =~ UNSAFE_REF_RX
          col = ($~.begin(0) || 0)
          results << finding(source, path, i + 1, col,
            "pull_request_target + PR-head checkout — attacker PR runs with write-scope token (T1195)")
          checkout_line = 0
        end
      end
      results
    end
  end
end
