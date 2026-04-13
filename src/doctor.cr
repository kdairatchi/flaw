require "yaml"
require "colorize"

module Flaw
  # `flaw doctor` — self-consistency audit of a flaw rules repo.
  # Complements `lint-rules` by catching drift *between* detectors, folders,
  # catalogs, and config.
  module Doctor
    record Check, name : String, ok : Bool, detail : String

    def self.run : Int32
      checks = [] of Check

      # 1. registered rules must have a rules/FLAWxxx folder
      Rule.all.each do |r|
        dir = File.join("rules", r.id)
        checks << Check.new("rule folder exists for #{r.id}", Dir.exists?(dir), dir)
      end

      # 2. rules/FLAWxxx folders must have a registered detector
      if Dir.exists?("rules")
        Dir.children("rules").select { |c| c.starts_with?("FLAW") && File.directory?(File.join("rules", c)) }.each do |dir|
          registered = Rule.all.any? { |r| r.id == dir }
          checks << Check.new("detector registered for rules/#{dir}", registered,
            registered ? "registered" : "no detector class — src/rules/ missing the implementation")
        end
      end

      # 3. each src/rules/*.cr (except rule.cr) should be referenced by at least one rule.yml
      detectors_on_disk = Dir.glob("src/rules/*.cr").map { |p| File.basename(p, ".cr") }
      detectors_on_disk.delete("rule")
      referenced = Set(String).new
      Dir.glob("rules/FLAW*/rule.yml").each do |path|
        raw = YAML.parse(File.read(path))
        if det = raw["detector"]?.try(&.as_s?)
          referenced << det
        end
      rescue
        # ignore — lint-rules surfaces yaml errors
      end
      detectors_on_disk.each do |d|
        ok = referenced.includes?(d)
        checks << Check.new("src/rules/#{d}.cr referenced by a rule.yml", ok,
          ok ? "referenced" : "orphan detector — add a rule.yml or delete it")
      end

      # 4. README catalog in rules/README.md references every rule
      readme_path = "rules/README.md"
      if File.exists?(readme_path)
        readme = File.read(readme_path)
        Rule.all.each do |r|
          ok = readme.includes?(r.id)
          checks << Check.new("rules/README.md lists #{r.id}", ok, ok ? "listed" : "missing from catalog")
        end
      end

      # 5. .flaw.yml parses if present
      if File.exists?(".flaw.yml")
        begin
          YAML.parse(File.read(".flaw.yml"))
          checks << Check.new(".flaw.yml valid YAML", true, "ok")
        rescue ex
          checks << Check.new(".flaw.yml valid YAML", false, ex.message || "parse error")
        end
      end

      report(checks)
      checks.any? { |c| !c.ok } ? 1 : 0
    end

    private def self.report(checks : Array(Check)) : Nil
      failing = checks.reject(&.ok)
      passing = checks.count(&.ok)
      checks.each do |c|
        if c.ok
          puts "  #{"✓".colorize(:green)} #{c.name}"
        else
          puts "  #{"✗".colorize(:red)} #{c.name}"
          puts "      #{c.detail}".colorize(:dark_gray)
        end
      end
      puts
      if failing.empty?
        puts "flaw doctor: #{passing} checks passed ✓".colorize(:green)
      else
        puts "flaw doctor: #{passing} passed, #{failing.size} failed".colorize(:red)
      end
    end
  end
end
