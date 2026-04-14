require "yaml"
require "colorize"

module Flaw
  # `flaw lint-rules` — validates the `rules/` directory against the contract
  # documented in rules/README.md. Intended to be the gatekeeper for
  # community rule contributions.
  module LintRules
    REQUIRED_FILES  = %w[rule.yml README.md]
    REQUIRED_FIXTURES = %w[bad good]
    FIXTURE_EXTS    = %w[.cr .py .js .jsx .ts .tsx .go .rs .java .kt .swift .php .rb .ex .exs .c .cpp .h .hpp .cs .scala .sh .ps1 .yml .yaml .json .tf .hcl .html .css .scss .sass .less .vue .svelte .astro .mjs .cjs .dockerfile]
    REQUIRED_KEYS   = %w[id title severity tags detector]

    def self.find_fixture(dir_path : String, name : String) : String?
      FIXTURE_EXTS.each do |ext|
        p = File.join(dir_path, "#{name}#{ext}")
        return p if File.exists?(p)
      end
      # Also match dotfile-style names like `.mcp.json` or `.claude/settings.json`.
      Dir.glob(File.join(dir_path, "#{name}.*")).first?
    end

    record Issue, rule : String, level : Symbol, message : String

    def self.run(root : String = "rules") : Int32
      unless Dir.exists?(root)
        STDERR.puts "flaw: #{root}/ not found — run from a flaw rules repo"
        return 2
      end

      issues = [] of Issue
      dirs = Dir.children(root).select { |c| File.directory?(File.join(root, c)) }.sort

      if dirs.empty?
        puts "flaw: no rule directories under #{root}/"
        return 0
      end

      all_rules = Rule.all.to_h { |r| {r.id, r} }

      dirs.each do |dir|
        path = File.join(root, dir)
        unless dir =~ /\AFLAW\d{3}\z/
          issues << Issue.new(dir, :error, "directory name must match FLAWNNN")
          next
        end

        REQUIRED_FILES.each do |f|
          unless File.exists?(File.join(path, f))
            issues << Issue.new(dir, :error, "missing #{f}")
          end
        end

        REQUIRED_FIXTURES.each do |name|
          unless find_fixture(path, name)
            issues << Issue.new(dir, :warn, "missing #{name}.<ext> fixture")
          end
        end

        yml_path = File.join(path, "rule.yml")
        if File.exists?(yml_path)
          check_rule_yml(dir, yml_path, all_rules, issues)
        end

        rule = all_rules[dir]?
        if rule && (bad_path = find_fixture(path, "bad"))
          findings = Scanner.new([rule], Config.new([] of String)).scan(bad_path)
          if findings.none? { |f| f.rule_id == dir }
            issues << Issue.new(dir, :error, "bad fixture does not fire #{dir}")
          end
        end
        if rule && (good_path = find_fixture(path, "good"))
          findings = Scanner.new([rule], Config.new([] of String)).scan(good_path)
          if findings.any? { |f| f.rule_id == dir }
            issues << Issue.new(dir, :error, "good fixture falsely fires #{dir}")
          end
        end

        if rule && (fp_path = find_fixture(path, "fp"))
          findings = Scanner.new([rule], Config.new([] of String)).scan(fp_path)
          if findings.any? { |f| f.rule_id == dir }
            issues << Issue.new(dir, :error, "fp fixture falsely fires #{dir} — tighten the detector")
          end
        end

        if rule.nil? && File.exists?(yml_path)
          issues << Issue.new(dir, :warn, "no detector registered for #{dir} — check src/rules/*.cr")
        end
      end

      report(dirs, issues)
      issues.any?(&.level.== :error) ? 1 : 0
    end

    private def self.check_rule_yml(dir : String, path : String, rules : Hash(String, Rule), issues) : Nil
      begin
        raw = YAML.parse(File.read(path))
      rescue ex
        issues << Issue.new(dir, :error, "rule.yml is not valid YAML: #{ex.message}")
        return
      end

      REQUIRED_KEYS.each do |k|
        unless raw[k]?
          issues << Issue.new(dir, :error, "rule.yml missing required key '#{k}'")
        end
      end

      if (yid = raw["id"]?.try(&.as_s?)) && yid != dir
        issues << Issue.new(dir, :error, "rule.yml id='#{yid}' does not match directory '#{dir}'")
      end
      if (sev = raw["severity"]?.try(&.as_s?)) && Severity.parse?(sev).nil?
        issues << Issue.new(dir, :error, "rule.yml severity='#{sev}' is not info/low/medium/high/critical")
      end
      if (tags = raw["tags"]?) && tags.as_a?.nil?
        issues << Issue.new(dir, :error, "rule.yml tags must be a list")
      end

      if (det = raw["detector"]?.try(&.as_s?)) && !File.exists?("src/rules/#{det}.cr")
        issues << Issue.new(dir, :warn, "detector src/rules/#{det}.cr not found")
      end

      if (yseverity = raw["severity"]?.try(&.as_s?)) && (rule = rules[dir]?)
        if Severity.parse?(yseverity) != rule.default_severity
          issues << Issue.new(dir, :warn, "rule.yml severity='#{yseverity}' disagrees with detector's default_severity='#{rule.default_severity.label}'")
        end
      end
    end

    private def self.report(dirs : Array(String), issues : Array(Issue)) : Nil
      by_rule = issues.group_by(&.rule)
      ok = 0
      dirs.each do |dir|
        problems = by_rule[dir]? || [] of Issue
        if problems.empty?
          puts "  #{"✓".colorize(:green)}  #{dir}"
          ok += 1
        else
          status = problems.any?(&.level.== :error) ? "✗".colorize(:red) : "!".colorize(:yellow)
          puts "  #{status}  #{dir}"
          problems.each do |p|
            tag = p.level == :error ? "error".colorize(:red) : "warn".colorize(:yellow)
            puts "       #{tag} #{p.message}"
          end
        end
      end
      err_count  = issues.count(&.level.== :error)
      warn_count = issues.count(&.level.== :warn)
      puts
      if issues.empty?
        puts "flaw: all #{dirs.size} rules valid ✓".colorize(:green)
      else
        puts "flaw: #{ok}/#{dirs.size} clean, #{err_count} errors, #{warn_count} warnings".colorize(err_count > 0 ? :red : :yellow)
      end
    end
  end
end
