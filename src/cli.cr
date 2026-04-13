require "option_parser"
require "colorize"
require "./branding"
require "./cli/regex_cmd"

module Flaw
  module CLI
    FORMATS = %w[pretty json sarif]

    def self.run(argv : Array(String)) : Nil
      Colorize.enabled = Branding.color_enabled?
      subcommand = argv.shift? || "scan"

      case subcommand
      when "version", "--version"
        puts "flaw #{Flaw::VERSION}"
      when "banner"
        Branding.banner
      when "rules"
        show_rules(argv)
      when "lint-rules"
        exit(LintRules.run(argv.first? || "rules"))
      when "doctor"
        exit(Doctor.run)
      when "baseline"
        exit(baseline_cmd(argv))
      when "init"
        init(argv)
      when "regex"
        RegexCmd.run(argv)
      when "scan"
        scan(argv)
      when "help", "--help", "-h"
        print_help
      else
        STDERR.puts "flaw: unknown command '#{subcommand}' — try `flaw help`"
        exit 2
      end
    end

    private def self.scan(argv : Array(String)) : Nil
      format = "pretty"
      fail_on = "medium"
      config_path = ".flaw.yml"
      baseline_path : String? = nil
      include_tags = [] of String
      exclude_tags = [] of String
      paths = [] of String
      verbose = false
      quiet = false
      no_banner = false

      parser = OptionParser.new do |p|
        p.banner = "usage: flaw scan [options] [path...]"
        p.on("--format FORMAT", "Output format: #{FORMATS.join(", ")}") { |v| format = v }
        p.on("--fail-on LEVEL", "Fail if any finding >= LEVEL (info/low/medium/high/critical)") { |v| fail_on = v }
        p.on("--config FILE", "Config file (default: .flaw.yml)") { |v| config_path = v }
        p.on("--baseline FILE", "Suppress findings listed in baseline file") { |v| baseline_path = v }
        p.on("--include-tag TAG", "Only run rules with TAG (repeatable)") { |v| include_tags << v }
        p.on("--exclude-tag TAG", "Skip rules with TAG (repeatable)") { |v| exclude_tags << v }
        p.on("-v", "--verbose", "Print rule count, per-path progress, and timing") { verbose = true }
        p.on("-q", "--quiet", "Suppress the summary footer") { quiet = true }
        p.on("--no-banner", "Suppress the banner header") { no_banner = true }
        p.on("--no-color", "Disable ANSI colors") { Colorize.enabled = false }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args do |args, _|
          paths.concat(args)
        end
      end
      parser.parse(argv)

      paths << "." if paths.empty?
      unless FORMATS.includes?(format)
        STDERR.puts "flaw: bad --format '#{format}'"
        exit 2
      end
      threshold = Severity.parse?(fail_on)
      unless threshold
        STDERR.puts "flaw: bad --fail-on '#{fail_on}'"
        exit 2
      end

      config = Config.load(config_path)
      selected = Rule.all
      selected = selected.select { |r| include_tags.includes?(r.tag) } unless include_tags.empty?
      selected = selected.reject { |r| exclude_tags.includes?(r.tag) } unless exclude_tags.empty?

      show_header = format == "pretty" && !no_banner && !quiet
      Branding.banner(STDERR) if show_header
      if verbose
        STDERR.puts "flaw: #{selected.size} rules active · paths=#{paths.join(", ")}".colorize(:dark_gray)
      end

      scanner = Scanner.new(selected, config)
      all = [] of Finding
      started = Time.instant
      paths.each do |p|
        if verbose
          t0 = Time.instant
          found = scanner.scan(p)
          STDERR.puts "  scanned #{p} · #{found.size} findings · #{(Time.instant - t0).total_milliseconds.round(1)}ms".colorize(:dark_gray)
          all.concat(found)
        else
          all.concat(scanner.scan(p))
        end
      end
      elapsed = Time.instant - started

      if bp = baseline_path
        all = Baseline.filter(all, Baseline.load(bp))
      end

      case format
      when "pretty" then Formatters::Pretty.render(all, STDOUT, quiet: quiet)
      when "json"   then Formatters::JsonFmt.render(all)
      when "sarif"  then Formatters::Sarif.render(all)
      end

      if verbose && format == "pretty" && !quiet
        STDERR.puts "flaw: scan took #{elapsed.total_seconds.round(2)}s".colorize(:dark_gray)
      end

      hit = all.any? { |f| f.severity >= threshold }
      exit(hit ? 1 : 0)
    end

    private def self.show_rules(argv : Array(String)) : Nil
      if id = argv.first?
        rule = Rule.all.find { |r| r.id == id.upcase }
        unless rule
          STDERR.puts "flaw: no rule '#{id}'"
          exit 2
        end
        puts "#{rule.id}  #{rule.title}".colorize(:white).mode(:bold)
        puts "severity: #{rule.default_severity.label}"
        puts
        puts rule.description
      else
        puts "flaw built-in rules:"
        Rule.all.group_by(&.tag).each do |tag, group|
          puts
          puts "  [#{tag}]".colorize(:white).mode(:bold)
          group.sort_by(&.id).each do |r|
            puts "    #{r.id}  [#{r.default_severity.label.ljust(8)}]  #{r.title}"
          end
        end
        puts
        puts "run `flaw rules FLAW001` to see details for a rule."
      end
    end

    private def self.init(argv : Array(String)) : Nil
      kind = argv.shift? || "config"
      case kind
      when "config"
        init_config(argv.first? || ".flaw.yml")
      when "rule"
        id   = argv.shift? || (STDERR.puts "flaw: usage: flaw init rule FLAWNNN slug"; exit 2)
        slug = argv.shift? || (STDERR.puts "flaw: usage: flaw init rule FLAWNNN slug"; exit 2)
        init_rule(id, slug)
      else
        STDERR.puts "flaw: init needs 'config' or 'rule'"
        exit 2
      end
    end

    private def self.init_config(path : String) : Nil
      if File.exists?(path)
        STDERR.puts "flaw: #{path} already exists"
        exit 1
      end
      File.write(path, <<-YAML)
      # flaw configuration — https://github.com/kdairatchi/flaw
      version: 1

      exclude:
        - spec/
        - lib/
        - vendor/

      rules:
        # FLAW001: {severity: critical}
        # FLAW002:
        #   ignore:
        #     - "examples/fake-keys.cr"
        # FLAW005: {disabled: true}
      YAML
      puts "flaw: wrote #{path}"
    end

    private def self.init_rule(id : String, slug : String) : Nil
      id = id.upcase
      unless id =~ /\AFLAW\d{3}\z/
        STDERR.puts "flaw: rule id must match FLAWNNN (got '#{id}')"
        exit 2
      end
      snake = slug.downcase.gsub(/[^a-z0-9]+/, "_").strip('_')
      class_name = snake.split('_').map(&.capitalize).join
      dir = File.join("rules", id)
      if Dir.exists?(dir)
        STDERR.puts "flaw: #{dir} already exists"
        exit 1
      end
      Dir.mkdir_p(dir)
      File.write(File.join(dir, "rule.yml"), <<-YAML)
      id: #{id}
      title: TODO one-line description
      severity: medium
      tags: [todo]
      owasp: TODO — category
      cwe: CWE-TODO
      detector: #{snake}
      YAML
      File.write(File.join(dir, "bad.cr"), <<-CR)
      # #{id} — vulnerable fixture. Must trigger the rule.
      # TODO: real vulnerable pattern here.
      CR
      File.write(File.join(dir, "good.cr"), <<-CR)
      # #{id} — fixed fixture. Must NOT trigger the rule.
      # TODO: safe equivalent here.
      CR
      File.write(File.join(dir, "README.md"), <<-MD)
      # #{id} — TODO title

      **Severity:** medium · **Tag:** todo

      ## What

      TODO.

      ## Fix

      TODO.
      MD

      detector_path = File.join("src", "rules", "#{snake}.cr")
      unless File.exists?(detector_path)
        Dir.mkdir_p(File.dirname(detector_path))
        File.write(detector_path, <<-CR)
        require "./rule"

        module Flaw
          class #{class_name} < Rule
            def id : String
              "#{id}"
            end

            def title : String
              "TODO title"
            end

            def default_severity : Severity
              Severity::Medium
            end

            def description : String
              "TODO description"
            end

            def check(source : String, path : String) : Array(Finding)
              results = [] of Finding
              # TODO: implement detection.
              results
            end
          end
        end
        CR
      end

      puts "flaw: scaffolded #{dir}/ and #{detector_path}"
      puts "flaw: next — implement the detector, fill the fixtures, add to rules/README.md"
    end

    private def self.baseline_cmd(argv : Array(String)) : Int32
      out_path = ".flaw-baseline.json"
      config_path = ".flaw.yml"
      paths = [] of String
      parser = OptionParser.new do |p|
        p.banner = "usage: flaw baseline [--out FILE] [--config FILE] [path...]"
        p.on("--out FILE", "Baseline output path (default .flaw-baseline.json)") { |v| out_path = v }
        p.on("--config FILE", "Config file") { |v| config_path = v }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |args, _| paths.concat(args) }
      end
      parser.parse(argv)
      paths << "." if paths.empty?
      scanner = Scanner.new(Rule.all, Config.load(config_path))
      all = [] of Finding
      paths.each { |p| all.concat(scanner.scan(p)) }
      Baseline.save(all, out_path)
      puts "flaw: wrote #{all.size} findings to #{out_path}"
      0
    end

    private def self.print_help : Nil
      Branding.banner
      puts
      puts <<-HELP
      flaw #{Flaw::VERSION} — find security flaws in Crystal code

      usage:
        flaw scan [--format pretty|json|sarif] [--fail-on LEVEL]
                  [--baseline FILE] [--include-tag TAG] [--exclude-tag TAG] [path...]
        flaw rules [RULE_ID]
        flaw lint-rules [rules_dir]
        flaw doctor
        flaw baseline [--out FILE] [path...]
        flaw init config [PATH]
        flaw init rule FLAWNNN slug
        flaw regex test <pattern> <input>
        flaw regex help
        flaw banner
        flaw version

      env:
        NO_COLOR / FLAW_NO_COLOR   disable ANSI colors (or use --no-color)
        flaw help

      docs:  https://github.com/kdairatchi/flaw
      HELP
    end
  end
end
