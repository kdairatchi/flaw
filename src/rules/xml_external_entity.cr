require "./rule"

module Flaw
  # FLAW014 — XXE. XML::Reader / XML.parse with untrusted input and default
  # libxml2 flags (which resolve external entities).
  class XmlExternalEntity < Rule
    def id : String
      "FLAW014"
    end

    def title : String
      "XML parsed without disabling external entities (XXE)"
    end

    def default_severity : Severity
      Severity::High
    end

    def description : String
      <<-DESC
      Crystal's XML module wraps libxml2, which resolves external entities by
      default. Parsing attacker-controlled XML allows file disclosure via
      `<!ENTITY xxe SYSTEM "file:///etc/passwd">` and SSRF via http://. Pass
      `XML::ParserOptions::NONET | XML::ParserOptions::NOENT.invert` and
      validate the payload out-of-band.
      DESC
    end

    PATTERNS = [
      /\bXML\.parse\s*\(/,
      /\bXML::Reader\.new\s*\(/,
    ]
    SAFE_HINT = /NONET|NOENT|noent: *false/

    def check(source : String, path : String) : Array(Finding)
      results = [] of Finding
      source.each_line.with_index(1) do |line, idx|
        next if line.lstrip.starts_with?('#')
        PATTERNS.each do |re|
          if m = line.match(re)
            next if line =~ SAFE_HINT
            results << finding(source, path, idx, m.begin(0) || 0,
              "Parsing XML without disabling external entities — pass NONET and resolve-external-entities: false")
            break
          end
        end
      end
      results
    end
  end
end
