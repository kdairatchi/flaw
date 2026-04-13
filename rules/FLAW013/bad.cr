require "random"

def stash(content : String)
  File.write(File.tempname("upload", ".txt"), content)
end

def quick_cache(content : String)
  File.write("/tmp/cache-#{rand(10000)}", content)
end
