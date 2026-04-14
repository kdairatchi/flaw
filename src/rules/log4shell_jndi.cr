require "./rule"
require "./context"

module Flaw
  # FLAW132 — Log4Shell JNDI payload string in source.
  class Log4ShellJndi < Rule
    def id : String
      "FLAW132"
    end

    def title : String
      "Log4Shell JNDI payload"
    end

    def default_severity : Severity
      Severity::Critical
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      The ${jndi:...} payload string is the Log4Shell exploit trigger
      (CVE-2021-44228). Finding it in source usually means either a test
      fixture, an embedded exploit, or a deny-list regex. All three are
      worth eyeballing.
      DESC
    end

    RX = /\$\{jndi:(ldap|ldaps|rmi|dns|iiop|http|nis|nds|corba)[^}]*\}/i

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding if RuleContext.lock_path?(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        if m = line.match(RX)
          results << finding(source, path, idx, m.begin(0) || 0,
            "Log4Shell JNDI payload string in source — if this is not a sanitizer pattern, it's an embedded exploit")
        end
      end
      results
    end
  end
end
