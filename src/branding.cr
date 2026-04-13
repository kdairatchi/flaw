require "colorize"

module Flaw
  module Branding
    BANNER = <<-'ART'
      ╔═╗╦  ╔═╗╦ ╦
      ╠╣ ║  ╠═╣║║║
      ╚  ╩═╝╩ ╩╚╩╝
    ART

    TAGLINE = "static analysis for Crystal — kdairatchi · ProwlrBot"

    # Respects NO_COLOR (https://no-color.org) and non-TTY stdout.
    def self.color_enabled? : Bool
      return false if ENV["NO_COLOR"]?
      return false if ENV["FLAW_NO_COLOR"]?
      STDOUT.tty?
    end

    def self.banner(io : IO = STDOUT) : Nil
      if color_enabled?
        io.puts BANNER.colorize(:magenta).mode(:bold)
        io.puts "  #{TAGLINE}".colorize(:dark_gray)
        io.puts "  v#{Flaw::VERSION} · https://github.com/kdairatchi/flaw".colorize(:dark_gray)
      else
        io.puts BANNER
        io.puts "  #{TAGLINE}"
        io.puts "  v#{Flaw::VERSION} · https://github.com/kdairatchi/flaw"
      end
    end
  end
end
