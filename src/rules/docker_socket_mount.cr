require "./rule"
require "./context"

module Flaw
  # FLAW143 — /var/run/docker.sock mounted into a container (escape to host).
  class DockerSocketMount < Rule
    def id : String
      "FLAW143"
    end

    def title : String
      "Docker socket mounted into container"
    end

    def default_severity : Severity
      Severity::High
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      Mounting `/var/run/docker.sock` into a container gives that container
      full control of the Docker daemon — equivalent to root on the host.
      Use a rootless pattern, socket proxy with strict allow-list, or
      remote API with TLS client certs instead.
      DESC
    end

    SOCK_RX = /\/var\/run\/docker\.sock/

    EXTS = %w(.yml .yaml .sh .bash .zsh)

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding if RuleContext.test_path?(path) || RuleContext.doc_path?(path)
      base = path.split('/').last
      ok = EXTS.any? { |e| path.ends_with?(e) } ||
           base == "Dockerfile" || base.starts_with?("Dockerfile") ||
           base == "docker-compose.yml" || base == "docker-compose.yaml"
      return [] of Finding unless ok
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        if m = line.match(SOCK_RX)
          results << finding(source, path, idx, m.begin(0) || 0,
            "Docker socket mounted into container — instant container escape to host root")
        end
      end
      results
    end
  end
end
