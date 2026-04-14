require "./rule"
require "./context"

module Flaw
  # FLAW131 — autocomplete="off" on credential-like inputs. Harms password
  # managers; modern browsers ignore it on password fields anyway.
  class AutocompleteOff < Rule
    def id : String
      "FLAW131"
    end

    def title : String
      %(autocomplete="off" on credential field)
    end

    def default_severity : Severity
      Severity::Low
    end

    def tag : String
      "a11y"
    end

    def description : String
      <<-DESC
      Setting autocomplete="off" on a password / email / username / tel
      input breaks password managers, which hurts both accessibility and
      security (users reuse weaker passwords when managers can't help).
      Modern browsers ignore autocomplete="off" on password fields, so
      this only succeeds at harming legitimate use. Remove the attribute
      or use a specific token like "new-password" / "current-password".
      DESC
    end

    EXTS     = %w(.html .htm .jsx .tsx .vue .svelte .astro .erb .ecr .hbs .liquid .php)
    INPUT_RX = /<input\b[^>]*>/i
    TYPE_RX  = /\btype\s*=\s*(?:"|')(password|email|tel|username|text)(?:"|')/i
    AC_RX    = /\bautocomplete\s*=\s*(?:"|')off(?:"|')/i
    NAME_RX  = /\bname\s*=\s*(?:"|')(?:username|email|user|login)(?:"|')/i

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless EXTS.any? { |ext| path.ends_with?(ext) }
      return [] of Finding if RuleContext.test_path?(path)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        if m = line.match(INPUT_RX)
          tag = m[0]
          tm = tag.match(TYPE_RX)
          next unless tm
          next unless tag =~ AC_RX
          type_val = tm[1].downcase
          if type_val == "text"
            next unless tag =~ NAME_RX
          end
          results << finding(source, path, idx, m.begin(0) || 0,
            %(autocomplete="off" on credential field — harms password managers; browsers ignore this on passwords anyway))
        end
      end
      results
    end
  end
end
