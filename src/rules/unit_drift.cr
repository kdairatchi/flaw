require "./rule"
require "./context"

module Flaw
  # FLAW111 — unit drift in stylesheets. Mixing px/rem/em within the same
  # property family (spacing or sizing) in a single file means the design
  # didn't settle on a scale. Pick one unit per family.
  class UnitDrift < Rule
    def id : String
      "FLAW111"
    end

    def title : String
      "Mixed CSS units within property family"
    end

    def default_severity : Severity
      Severity::Low
    end

    def tag : String
      "design"
    end

    def description : String
      <<-DESC
      A single stylesheet/component file mixes more than one unit
      (px/rem/em) within the same property family (spacing:
      margin/padding/gap, or sizing: width/height/font-size).
      Standardise on one unit per family so the scale is legible.
      DESC
    end

    STYLE_EXTS = %w(.css .scss .sass .less .vue .svelte .jsx .tsx .html)
    PROP_RX    = /\b(margin|padding|gap|width|height|font-size)\s*:\s*([^;]+);?/
    UNIT_RX    = /\d+\.?\d*(px|rem|em)\b/

    SPACING = %w(margin padding gap)
    SIZING  = %w(width height font-size)

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding unless STYLE_EXTS.any? { |ext| path.ends_with?(ext) }

      # family => unit => {line, col}
      per_family = {
        "spacing" => {} of String => {Int32, Int32},
        "sizing"  => {} of String => {Int32, Int32},
      }

      source.each_line.with_index(1) do |line, idx|
        next if RuleContext.comment_only?(line)
        line.scan(PROP_RX) do |m|
          prop = m[1]
          value = m[2]
          family = if SPACING.includes?(prop)
                     "spacing"
                   elsif SIZING.includes?(prop)
                     "sizing"
                   else
                     next
                   end
          value.scan(UNIT_RX) do |um|
            unit = um[1]
            bucket = per_family[family]
            unless bucket.has_key?(unit)
              col = line.index(unit) || 0
              bucket[unit] = {idx, col}
            end
          end
        end
      end

      results = [] of Finding
      per_family.each do |family, bucket|
        next if bucket.size <= 1
        # Find the majority unit; emit at the first occurrence of each minority.
        # Simpler: emit one finding at the earliest-seen minority unit overall.
        # Determine majority by first-seen (stable tie-break).
        sorted = bucket.to_a.sort_by { |(_unit, pos)| pos[0] }
        majority_unit = sorted.first[0]
        sorted.each do |(unit, pos)|
          next if unit == majority_unit
          line_no, col = pos
          results << finding(source, path, line_no, col,
            "Mixed #{family} units — '#{unit}' conflicts with '#{majority_unit}' used elsewhere in this file")
          break
        end
      end
      results
    end
  end
end
