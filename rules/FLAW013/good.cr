def stash(content : String)
  File.tempfile("upload", ".txt") do |f|
    f.print content
    f.path
  end
end
