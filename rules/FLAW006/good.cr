# FLAW006 — fixed: normalise + confine to an allowed root
ROOT = "/var/www/uploads"

def safe_read(name : String) : String?
  candidate = File.expand_path(File.join(ROOT, name))
  return nil unless candidate.starts_with?(ROOT + "/")
  return nil unless File.file?(candidate)
  File.read(candidate)
end

puts safe_read("report.txt")
