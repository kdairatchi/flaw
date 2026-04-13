# Writing a known filename, not an archive entry
def write_report(dest : String, data : String)
  File.open(File.join(dest, "report.txt"), "w") do |f|
    f.puts data
  end
end
