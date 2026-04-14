require "./rule"
require "./context"

module Flaw
  # FLAW148 — source map shipped in a production artifact.
  # `sourceMappingURL` in a bundle under dist/build/out/lib (or a `.map`
  # listed in package.json `files:`) reconstructs readable source for
  # anyone who pulls the package. Strip before publishing.
  class SourceMapShipped < Rule
    def id : String
      "FLAW148"
    end

    def title : String
      "Source map shipped in production artifact"
    end

    def default_severity : Severity
      Severity::Medium
    end

    def tag : String
      "security"
    end

    def description : String
      <<-DESC
      A `sourceMappingURL` pragma was found in a bundle under a published
      artifact path (dist/, build/, out/, lib/), or a `.map` filename is
      listed in package.json's `files:` allowlist. Shipping source maps
      reconstructs the original TypeScript/JavaScript for anyone who pulls
      the package — strip them from the published tarball.
      DESC
    end

    ARTIFACT_PATH_RX = %r{(?:^|/)(?:dist|build|out|lib|public|_next|\.next|\.nuxt|\.output)/}i
    SOURCEMAP_RX     = %r{//[#@]\s*sourceMappingURL\s*=}
    PKG_FILES_MAP_RX = /"[^"]*\.map"/

    def check(source : String, path : String) : Array(Finding)
      return [] of Finding if RuleContext.test_path?(path)
      return [] of Finding if RuleContext.doc_path?(path)
      results = [] of Finding
      base = path.split('/').last
      if base == "package.json"
        in_files = false
        source.each_line.with_index(1) do |line, idx|
          if line =~ /"files"\s*:\s*\[/
            in_files = true
          end
          if in_files
            if m = line.match(PKG_FILES_MAP_RX)
              results << finding(source, path, idx, m.begin(0) || 0,
                "`.map` in package.json files — source maps ship to npm")
            end
            in_files = false if line.includes?(']')
          end
        end
        return results
      end
      return results unless ARTIFACT_PATH_RX.match(path)
      return results unless path =~ /\.(js|mjs|cjs|css)$/
      source.each_line.with_index(1) do |line, idx|
        if m = line.match(SOURCEMAP_RX)
          results << finding(source, path, idx, m.begin(0) || 0,
            "sourceMappingURL in production bundle — strip before publish")
          break
        end
      end
      results
    end
  end
end
