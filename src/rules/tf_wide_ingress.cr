require "./rule"
require "./context"

module Flaw
  # FLAW147 — Terraform / CloudFormation security group rule exposing ingress
  # to the entire internet (0.0.0.0/0). Noisy on web tiers; baseline those and
  # fix the rest.
  class TfWideIngress < Rule
    def id : String
      "FLAW147"
    end

    def title : String
      "Security group 0.0.0.0/0 ingress"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      A security group that allows ingress from 0.0.0.0/0 exposes the service
      to the entire internet. Legitimate for public HTTP/HTTPS load balancers;
      almost never correct for SSH, databases, admin consoles, or internal
      services. Restrict to a known CIDR, or a load-balancer security group.
      DESC
    end

    TF_RX  = /cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0\/0["']\s*\]/
    CFN_RX = /CidrIp\s*:\s*0\.0\.0\.0\/0/

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding if RuleContext.test_path?(path) || RuleContext.doc_path?(path)

      is_tf = path.ends_with?(".tf") || path.ends_with?(".tf.json")
      is_cfn = path.ends_with?(".yml") || path.ends_with?(".yaml") || path.ends_with?(".json")
      return [] of Finding unless is_tf || is_cfn

      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        matched = nil
        if is_tf && (m = line.match(TF_RX))
          matched = m
        elsif is_cfn && (m = line.match(CFN_RX))
          matched = m
        end
        if matched
          results << finding(source, path, idx, matched.begin(0) || 0,
            "Security group allows 0.0.0.0/0 — world-open ingress; restrict to known CIDR")
        end
      end
      results
    end
  end
end
