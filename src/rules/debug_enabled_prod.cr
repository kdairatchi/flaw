require "./rule"
require "./context"

module Flaw
  # FLAW134 — Debug / permissive config enabled.
  class DebugEnabledProd < Rule
    def id : String
      "FLAW134"
    end

    def title : String
      "Debug enabled in config"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      Framework debug modes leak stack traces, enable interactive
      consoles, and disable security defaults. Shipping with DEBUG=True,
      ALLOWED_HOSTS=*, or NODE_ENV=development exposes the app.
      DESC
    end

    CODE_EXT = %w(.py .rb .js .jsx .ts .tsx .mjs .cjs .java .kt)
    CONF_EXT = %w(.yml .yaml .properties .toml .env)
    DEV_PATH = /\/(?:test|dev|development|staging)\.(?:yml|yaml|env|properties|toml)$/i

    PY_DEBUG   = /\bDEBUG\s*=\s*True\b/
    APP_DEBUG  = /\bapp\.debug\s*=\s*True\b/
    FLASK_RUN  = /\bapp\.run\s*\([^)]*debug\s*=\s*True/
    ALLOW_STAR = /\bALLOWED_HOSTS\s*=\s*\[?\s*["']\*["']/
    RAILS_LOC  = /\bconfig\.consider_all_requests_local\s*=\s*true\b/
    NODE_DEV   = /process\.env\.NODE_ENV\s*=\s*["']development["']/
    SPRING_DBG = /^\s*debug\s*=\s*true\b/

    def check(source : String, path : String) : Array(Finding)
      ext_ok = CODE_EXT.any? { |e| path.ends_with?(e) } || CONF_EXT.any? { |e| path.ends_with?(e) }
      return [] of Finding unless ext_ok
      return [] of Finding if RuleContext.test_path?(path) || RuleContext.doc_path?(path)
      return [] of Finding if path =~ DEV_PATH
      # Don't flag .env.example/.env.sample
      base = path.split('/').last
      return [] of Finding if base.ends_with?(".example") || base.ends_with?(".sample")

      is_spring = path.ends_with?(".properties") || path.ends_with?(".yml") || path.ends_with?(".yaml")
      patterns = [PY_DEBUG, APP_DEBUG, FLASK_RUN, ALLOW_STAR, RAILS_LOC, NODE_DEV]
      patterns << SPRING_DBG if is_spring

      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        patterns.each do |rx|
          if m = line.match(rx)
            results << finding(source, path, idx, m.begin(0) || 0,
              "Debug/permissive config enabled — verify this isn't shipped to production")
            break
          end
        end
      end
      results
    end
  end
end
