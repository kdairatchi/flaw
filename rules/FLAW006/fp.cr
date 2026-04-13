# FLAW006 — FP corpus: File.read with constant paths or safely normalised input
LOG = "/var/log/flaw.log"
File.read(LOG)

name = ENV["CONFIG_FILE"]? || "default.yml"
File.read(File.join("/etc/flaw", name)) if name =~ /\A[a-z0-9_.-]+\z/
